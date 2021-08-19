import "pkg/distributors/contracts/MerkleRedeem.sol";

pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

contract HarnessMerkle is MerkleRedeem {

    constructor(IVault _vault, IERC20 _rewardToken) MerkleRedeem(_vault, _rewardToken){}

    function Harness_claimTwoWeeks(address liquidityProvider, uint256 week1, uint256 balance1, bytes32[] calldata proof1, 
                                   uint256 week2, uint256 balance2, bytes32[] calldata proof2) external {
        require(msg.sender == liquidityProvider, "user must claim own balance");
        Claim memory a = Claim(week1, balance1, proof1);
        Claim memory b = Claim(week2, balance2, proof2);
        Claim[] memory claims = new Claim[](2);
        claims[0] = a;
        claims[1] = b;

        claimWeeks(liquidityProvider, claims);
    }
}