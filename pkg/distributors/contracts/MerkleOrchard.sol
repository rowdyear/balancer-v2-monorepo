// SPDX-License-Identifier: GPL-3.0-or-later
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pragma experimental ABIEncoderV2;

import "@balancer-labs/v2-solidity-utils/contracts/math/FixedPoint.sol";
import "@balancer-labs/v2-solidity-utils/contracts/openzeppelin/Ownable.sol";
import "@balancer-labs/v2-solidity-utils/contracts/openzeppelin/MerkleProof.sol";
import "@balancer-labs/v2-solidity-utils/contracts/openzeppelin/IERC20.sol";
import "@balancer-labs/v2-solidity-utils/contracts/openzeppelin/SafeERC20.sol";

import "@balancer-labs/v2-vault/contracts/interfaces/IVault.sol";
import "@balancer-labs/v2-vault/contracts/interfaces/IAsset.sol";

import "./interfaces/IDistributor.sol";
import "./interfaces/IDistributorCallback.sol";

pragma solidity ^0.7.0;

contract MerkleOrchard is IDistributor, Ownable {
    using FixedPoint for uint256;
    using SafeERC20 for IERC20;

    // Recorded distributions
    uint256 public nextDistributionNonce;
    // rewardToken > rewarder > distribution > root
    mapping(IERC20 => mapping(address => mapping(uint256 => bytes32))) public trees;
    // rewardToken > rewarder distribution > lp > root
    mapping(IERC20 => mapping(address => mapping(uint256 => mapping(address => bool)))) public claimed;
    // rewardToken > rewarder > balance
    mapping(IERC20 => mapping(address => uint256)) public suppliedBalance;

    IVault public immutable vault;

    constructor(IVault _vault) {
        vault = _vault;
    }

    struct Claim {
        uint256 distributionNonce;
        uint256 balance;
        address rewarder;
        IERC20 rewardToken;
        bytes32[] merkleProof;
    }

    function _processClaims(
        address liquidityProvider,
        address recipient,
        Claim[] memory claims,
        bool asInternalBalance
    ) internal {
        IVault.UserBalanceOpKind kind = asInternalBalance
            ? IVault.UserBalanceOpKind.TRANSFER_INTERNAL
            : IVault.UserBalanceOpKind.WITHDRAW_INTERNAL;
        IVault.UserBalanceOp[] memory ops = new IVault.UserBalanceOp[](claims.length);

        Claim memory claim;
        for (uint256 i = 0; i < claims.length; i++) {
            claim = claims[i];

            require(
                !isClaimed(claim.rewardToken, claim.rewarder, claim.distributionNonce, liquidityProvider),
                "cannot claim twice"
            );
            require(
                verifyClaim(
                    claim.rewardToken,
                    claim.rewarder,
                    liquidityProvider,
                    claim.distributionNonce,
                    claim.balance,
                    claim.merkleProof
                ),
                "Incorrect merkle proof"
            );

            require(
                suppliedBalance[claim.rewardToken][claim.rewarder] >= claim.balance,
                "rewarder hasn't provided sufficient rewardTokens for claim"
            );

            ops[i] = IVault.UserBalanceOp({
                asset: IAsset(address(claim.rewardToken)),
                amount: claim.balance,
                sender: address(this),
                recipient: payable(recipient),
                kind: kind
            });

            claimed[claim.rewardToken][claim.rewarder][claim.distributionNonce][liquidityProvider] = true;

            suppliedBalance[claim.rewardToken][claim.rewarder] =
                suppliedBalance[claim.rewardToken][claim.rewarder] -
                claim.balance;
            emit RewardPaid(recipient, address(claim.rewardToken), claim.balance);
        }
        vault.manageUserBalance(ops);
    }

    /**
     * @notice Allows a user to claim multiple distributions of reward
     */
    function claimDistributions(address liquidityProvider, Claim[] memory claims) external {
        require(msg.sender == liquidityProvider, "user must claim own balance");

        _processClaims(liquidityProvider, msg.sender, claims, false);
    }

    /**
     * @notice Allows a user to claim multiple distributions of reward to internal balance
     */
    function claimDistributionsToInternalBalance(address liquidityProvider, Claim[] memory claims) external {
        require(msg.sender == liquidityProvider, "user must claim own balance");

        _processClaims(liquidityProvider, msg.sender, claims, true);
    }

    /**
     * @notice Allows a user to claim several distributions of rewards to a callback
     */
    function claimDistributionsWithCallback(
        address liquidityProvider,
        IDistributorCallback callbackContract,
        bytes calldata callbackData,
        Claim[] memory claims
    ) external {
        require(msg.sender == liquidityProvider, "user must claim own balance");
        _processClaims(liquidityProvider, address(callbackContract), claims, true);
        callbackContract.distributorCallback(callbackData);
    }

    function isClaimed(
        IERC20 rewardToken,
        address rewarder,
        uint256 distributionNonce,
        address liquidityProvider
    ) public view returns (bool) {
        return claimed[rewardToken][rewarder][distributionNonce][liquidityProvider];
    }

    function verifyClaim(
        IERC20 rewardToken,
        address rewarder,
        address liquidityProvider,
        uint256 distributionNonce,
        uint256 claimedBalance,
        bytes32[] memory merkleProof
    ) public view returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(liquidityProvider, claimedBalance));
        return MerkleProof.verify(merkleProof, trees[rewardToken][rewarder][distributionNonce], leaf);
    }

    /**
     * @notice
     * Allows the owner to add funds to the contract as a merkle tree, These tokens will
     * be withdrawn from the sender
     * These will be pulled from the user
     */
    function seedAllocations(
        IERC20 rewardToken,
        bytes32 _merkleRoot,
        uint256 amount
    ) external {
        rewardToken.safeTransferFrom(msg.sender, address(this), amount);

        rewardToken.approve(address(vault), type(uint256).max);
        IVault.UserBalanceOp[] memory ops = new IVault.UserBalanceOp[](1);

        ops[0] = IVault.UserBalanceOp({
            asset: IAsset(address(rewardToken)),
            amount: amount,
            sender: address(this),
            recipient: payable(address(this)),
            kind: IVault.UserBalanceOpKind.DEPOSIT_INTERNAL
        });

        vault.manageUserBalance(ops);

        suppliedBalance[rewardToken][msg.sender] = suppliedBalance[rewardToken][msg.sender] + amount;
        trees[rewardToken][msg.sender][nextDistributionNonce] = _merkleRoot;
        nextDistributionNonce += 1;
        emit RewardAdded(address(rewardToken), amount);
    }
}
