import "pkg/pool-weighted/contracts/smart/InvestmentPool.sol";

pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

contract InvestmentPoolHarness is InvestmentPool {
    constructor (
        IVault vault,
        string memory name,
        string memory symbol,
        IERC20[] memory tokens,
        uint256[] memory normalizedWeights,
        address[] memory assetManagers,
        uint256 swapFeePercentage,
        uint256 pauseWindowDuration,
        uint256 bufferPeriodDuration,
        address owner,
        bool swapEnabledOnStart
    )
    InvestmentPool(
            vault,
            name,
            symbol,
            tokens,
            normalizedWeights,
            assetManagers,
            swapFeePercentage,
            pauseWindowDuration,
            bufferPeriodDuration,
            owner,
            swapEnabledOnStart
    ) {}
}