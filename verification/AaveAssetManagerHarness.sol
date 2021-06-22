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

    function Harness_capitalOut(uint256 amount) public {
        _capitalOut(amount);
    }

    function Harness_capitalIn(uint256 amount) public {
        _capitalIn(amount);
    }

    function Harness_getTargetPercentage() external view returns (uint256) {
        return _config.targetPercentage;
    }

    function Harness_getMaxTargetInvestment() external view returns (uint256) {
        return 0.95e18;
    }

}
