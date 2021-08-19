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

    function Harness_getRewardRate (
        IERC20 pool,
        address rewarder,
        IERC20 rewardsToken
    ) public view returns (uint256) {
        return rewardData[pool][rewarder][rewardsToken].rewardRate;
    }

    function Harness_getRewardDuration (
        IERC20 pool,
        address rewarder,
        IERC20 rewardsToken
    ) public view returns (uint256) {
        return rewardData[pool][rewarder][rewardsToken].rewardsDuration;
    }

    function Harness_getUnpaidRewards (
        IERC20 pool,
        address account,
        IERC20 rewardsToken
    ) public view returns (uint256) {
        return unpaidRewards[pool][account][rewardsToken];
    }

    function Harness_getPaidRewards (
        IERC20 pool,
        address rewarder,
        address account,
        IERC20 rewardsToken
    ) public view returns (uint256) {
        return userRewardPerTokenPaid[pool][rewarder][account][rewardsToken];
    }

    function Harness_getRewardPerTokenStored (
        IERC20 pool,
        address rewarder,
        IERC20 rewardsToken
    ) public view returns (uint256) {
        return rewardData[pool][rewarder][rewardsToken].rewardPerTokenStored;
    }

    function Harness_getRewardPeriodFinish (
        IERC20 pool,
        address rewarder,
        IERC20 rewardsToken
    ) public view returns (uint256) {
        return rewardData[pool][rewarder][rewardsToken].periodFinish;
    }

    function Harness_getBalance(IERC20 pool_token, address user) public view returns (uint256) {
        return _balances[pool_token][user];
    }

}