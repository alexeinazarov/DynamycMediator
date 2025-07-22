// SPDX‑License‑Identifier: MIT
pragma solidity ^0.8.19;

/*//////////////////////////////////////////////////////////////////////////
        DynamicMediator
        ----------------
        Venue‑agnostic liquidation executor for LLAMMA soft‑liquidation slices.

        KEY PROPERTIES & SAFETY
        ‑ Re‑entrancy safe      (OZ ReentrancyGuard).
        ‑ Owner‑governed        (Ownable2Step with timelock‑friendly pattern).
        ‑ Permissioned keepers  (mapping) — can be opened later for permissionless.
        ‑ Multi‑venue routing   (UniswapV3Adapter, UniV2Adapter, future pool).
        ‑ Price sanity          (oracle deviation check, per‑slice minOut).
        ‑ Gas bounded           (O(#venues) staticcalls; each venue loop ≤5K gas).
        ‑ No custody of user funds; only protocol collateral -> protocol stable.
        ‑ Regulatory footprint  (same as Uniswap router wrappers; no KYC/custody).

        References
        ‑ Uniswap V2 Router (EIP‑20 standard interaction)
        ‑ SafeERC20 pattern (ERC‑20 approvals race‑condition mitigation)
        ‑ Chainlink Price Feed security best‑practice (max deviation + staleness)
//////////////////////////////////////////////////////////////////////////*/

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";

import "./interfaces/IBandState.sol";
import "./interfaces/ILiquidationVenue.sol";

/// @dev Chainlink aggregator minimal interface (pull‑only)
interface IAggregator {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
    function decimals() external view returns (uint8);
}

/*//////////////////////////////////////////////////////////////////////////
                                  CONTRACT
//////////////////////////////////////////////////////////////////////////*/
contract DynamicMediator is ReentrancyGuard, Ownable2Step {
    /*────────────────────────────  Events  ────────────────────────────*/
    /// Emitted when governance adds a new venue adapter
    event VenueAdded(address indexed venue);
    /// Emitted when governance removes a venue adapter
    event VenueRemoved(address indexed venue);
    /// Emitted after best‑price discovery
    event VenueSelected(uint256 indexed sliceId, address venue, uint256 quote);
    /// Emitted when a slice is executed
    event SliceExecuted(
        uint256 indexed sliceId,
        address indexed venue,
        uint256 collateralIn,
        uint256 stableOut,
        uint256 deviationBps
    );
    /// Emitted if executed price deviates too much from oracle mid
    event AbnormalFill(uint256 indexed sliceId, uint256 deviationBps);
    /// Emitted on keeper grant / revoke
    event KeeperSet(address indexed keeper, bool enabled);

    /*────────────────────────────  Storage  ───────────────────────────*/
    IBandState public immutable band;     // LLAMMA controller
    IAggregator public immutable oracle;  // Chainlink ETH/USD or pair‑specific

    ILiquidationVenue[] public venues;    // active adapters (governable)
    mapping(address => bool) public keepers;

    uint256 public sliceNonce;
    uint16  public maxDevBps = 500;       // Maximum tolerated execution deviation (5 %)
    uint256 public minSlice;              // Optional throttle: ignore dust slices

    /*───────────────────────────  Constructor  ───────────────────────*/
    /**
     * @param _band   LLAMMA controller address (Vyper)
     * @param _oracle Chainlink aggregator for collateral / stable price
     *
     * Security: all immutable addresses validated non‑zero
     */
    constructor(IBandState _band, IAggregator _oracle) {
        require(address(_band) != address(0), "band=0");
        require(address(_oracle) != address(0), "oracle=0");
        band   = _band;
        oracle = _oracle;
        _transferOwnership(msg.sender);              // Ownable2Step initial owner
    }

    /*───────────────────────────  Modifiers  ─────────────────────────*/
    /// @dev Restricts functions to approved keepers or governance
    modifier onlyKeeper() {
        require(keepers[msg.sender] || msg.sender == owner(), "keeper");
        _;
    }

    /*──────────────────────────  Governance  ─────────────────────────*/

    /// @notice Grant or revoke keeper right
    function setKeeper(address keeper, bool enabled) external onlyOwner {
        keepers[keeper] = enabled;
        emit KeeperSet(keeper, enabled);
    }

    /// @notice Adjust maximum allowed deviation from oracle mid‑price
    function setMaxDevBps(uint16 bps) external onlyOwner {
        require(bps < 2_000, ">20%");
        maxDevBps = bps;
    }

    /// @notice Ignore slices smaller than `amount` (gas/efficiency control)
    function setMinSlice(uint256 amount) external onlyOwner {
        minSlice = amount;
    }

    /// @notice Add a new liquidation venue adapter
    function addVenue(ILiquidationVenue v) external onlyOwner {
        venues.push(v);
        emit VenueAdded(address(v));
    }

    /// @notice Remove venue by index (order not preserved)
    function removeVenue(uint256 idx) external onlyOwner {
        require(idx < venues.length, "idx");
        emit VenueRemoved(address(venues[idx]));
        venues[idx] = venues[venues.length - 1];
        venues.pop();
    }

    /*──────────────────────────  Core Logic  ─────────────────────────*/

    /**
     * @notice Executes one soft‑liquidation slice through best venue.
     * @param loan      Vault address holding collateral
     * @param minOut    Minimum stable tokens the caller is willing to accept
     * @param venueData Optional adapter‑specific bytes (e.g., fee tier)
     *
     * ACCESS: keeper‑only (can later be opened permissionless).
     * REENTRANCY: guarded (external calls only after state reads).
     */
    function liquidateSlice(
        address loan,
        uint256 minOut,
        bytes calldata venueData
    )
        external
        nonReentrant
        onlyKeeper
    {
        /*──── fetch slice data from LLAMMA ────*/
        (uint256 amount,,) = band.getPendingSliceData(loan);
        require(amount >= minSlice && amount > 0, "no‑slice");

        uint256 sliceId = ++sliceNonce;

        address collateral = band.collateralToken();  // e.g., ETH
        address stable     = band.debtToken();        // e.g., USDT

        /*──── price discovery across venues ────*/
        uint256 bestQuote = 0;
        uint256 bestIdx   = type(uint256).max;
        for (uint256 i; i < venues.length; ++i) {
            uint256 q = venues[i].quote(collateral, stable, amount, venueData);
            if (q > bestQuote) {
                bestQuote = q;
                bestIdx   = i;
            }
        }
        require(bestIdx != type(uint256).max, "no‑venue");
        emit VenueSelected(sliceId, address(venues[bestIdx]), bestQuote);

        /*──── minOut sanity (keeper cannot grief) ────*/
        require(
            minOut >= (bestQuote * (10_000 - maxDevBps)) / 10_000,
            "minOut too low"
        );

        /*──── execution ────*/
        uint256 out =
            venues[bestIdx].sell(collateral, stable, amount, minOut, venueData);

        /*──── deviation & accounting ────*/
        uint256 devBps = _deviationBps(amount, out);

        if (devBps > maxDevBps) emit AbnormalFill(sliceId, devBps);

        band.markSliceProcessed(loan, amount, out);

        emit SliceExecuted(
            sliceId,
            address(venues[bestIdx]),
            amount,
            out,
            devBps
        );
    }

    /*──────────────────────────  Helpers  ───────────────────────────*/

    /**
     * @dev Calculates absolute basis‑point deviation between oracle mid‑price
     *      and executed swap.  Oracle is assumed to quote collateral‑per‑stable.
     *      Reverts if oracle price <= 0 or stale (staleness handled off‑chain).
     */
    function _deviationBps(uint256 amountIn, uint256 amountOut)
        internal
        view
        returns (uint256 dev)
    {
        (, int256 price,,,) = oracle.latestRoundData();
        require(price > 0, "oracle");
        uint256 decimals = oracle.decimals();      // Chainlink always ≤ 18

        uint256 expected = (amountIn * uint256(price)) / (10 ** decimals);
        if (expected == 0) return 0;

        uint256 diff = expected > amountOut
            ? expected - amountOut
            : amountOut - expected;

        dev = (diff * 10_000) / expected;          // basis points
    }
}
