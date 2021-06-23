// This is a harness file for MultiRewards, used for verification

import "pkg/distributors/contracts/MultiRewards.sol";

pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

contract RewardsDistributorHarness is MultiRewards {
    constructor(IVault _vault) MultiRewards(_vault){}
}