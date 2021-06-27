// This is a harness file for MultiRewards, used for verification

import "pkg/distributors/contracts/MultiRewards.sol";

pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

contract RewardsDistributorHarness is MultiRewards {
    using EnumerableSet for EnumerableSet.AddressSet;
    
    constructor(IVault _vault) MultiRewards(_vault){}

    function Harness_num_whitelisters(IERC20 pool, IERC20 rewardsToken) external view returns (uint256) {
        return _whitelist[pool][rewardsToken].length();
    }

    function Harness_num_rewarders(IERC20 pool, IERC20 rewardsToken) external view returns (uint256) {
        return _rewarders[pool][rewardsToken].length();
    }
}