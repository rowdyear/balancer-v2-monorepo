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
        IAaveIncentivesController _aaveIncentives
    ) AaveATokenAssetManager(_vault, _token, _lendingPool, _aaveIncentives) {}

    function Harness_capitalOut(uint256 amount) public {
        _capitalOut(amount);
    }

    function Harness_capitalIn(uint256 amount) public {
        _capitalIn(amount);
    }

    function Harness_getTargetPercentage() external view returns (uint256) {
        return _config.targetPercentage;
    }

    function Harness_getLowerCriticalPercentage() external view returns (uint256) {
        return _config.lowerCriticalPercentage;
    }

    function Harness_getUpperCriticalPercentage() external view returns (uint256) {
        return _config.upperCriticalPercentage;
    }

    function Harness_getMaxTargetInvestment() external view returns (uint256) {
        return 1e18;
    }

}
