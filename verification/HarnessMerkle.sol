import "pkg/distributors/contracts/MerkleRedeem.sol";

pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

contract HarnessMerkle is MerkleRedeem {

    constructor(IVault _vault, IERC20 _rewardToken) MerkleRedeem(_vault, _rewardToken){}
}