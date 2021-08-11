// This is a harness file for MultiRewards, used for verification

import "pkg/distributors/contracts/MultiRewards.sol";

pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

contract RewardsDistributorHarness is MultiRewards {
    using EnumerableSet for EnumerableSet.AddressSet;
    
    constructor(IVault _vault) MultiRewards(_vault){}

    // function Harness_num_whitelisters(IERC20 pool, IERC20 rewardsToken) external view returns (uint256) {
    //     return _allowlist[pool][rewardsToken].length();
    // }

    function Harness_num_rewarders(IERC20 pool, IERC20 rewardsToken) external view returns (uint256) {
        return _rewarders[pool][rewardsToken].length();
    }

    function Harness_isReadyToDistribute(
        IERC20 pool,
        IERC20 rewardsToken,
        address rewarder
    ) public view returns (bool) {
        return _rewarders[pool][rewardsToken].contains(rewarder);
    }

    function Harness_getLastUpdateTime (
        IERC20 pool,
        address rewarder,
        IERC20 rewardsToken
    ) public view returns (uint256) {
        return rewardData[pool][rewarder][rewardsToken].lastUpdateTime;
    }
}