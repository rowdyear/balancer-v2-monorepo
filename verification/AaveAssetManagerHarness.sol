// This is a harness file for AaveATokenAssetManager, used for verification

import "pkg/asset-manager-utils/contracts/RewardsAssetManager.sol";
import "pkg/asset-manager-utils/contracts/AaveATokenAssetManager.sol";

pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

contract AaveAssetManagerHarness is AaveATokenAssetManager {

    constructor(
        IVault _vault,
        IERC20 _token,
        ILendingPool _lendingPool,
        IERC20 _aToken,
        IAaveIncentivesController _aaveIncentives,
        IERC20 _stkAave
    ) AaveATokenAssetManager(_vault, _token, _lendingPool, _aToken, _aaveIncentives, _stkAave) {}

    // Simplifying fee calculation
    mapping(uint256 => uint256) public amount_to_rebalance_fees;

    function _getRebalanceFee(
        uint256 poolCash,
        uint256 poolManaged,
        PoolConfig memory config
    ) internal view override returns (uint256) {
        if (poolCash == 0) return 0;
        uint256 _fee = amount_to_rebalance_fees[poolCash];
        require(_fee < poolCash);
        return _fee;
    }
}
