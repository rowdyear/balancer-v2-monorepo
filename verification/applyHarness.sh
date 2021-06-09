# fix imports
find . -type f -name "*.sol" -exec sed -i 's/@balancer-labs\/v2-/pkg\//g' {} +

# safeTransfers to transfers, safeTransferTo to transferTo
find . -type f -name "*.sol" -exec sed -i 's/safeT/t/g' {} +


# perl -0777 -i -pe 's/safeT/t/g' pkg/distributors/contracts/MerkleRedeem.sol
# perl -0777 -i -pe 's/safeT/t/g' pkg/distributors/contracts/MultiRewards.sol
# perl -0777 -i -pe 's/safeT/t/g' pkg/solidity-utils/contracts/openzeppelin/SafeERC20.sol
# perl -0777 -i -pe 's/safeT/t/g' pkg/vault/contracts/AssetManagers.sol
# perl -0777 -i -pe 's/safeT/t/g' pkg/vault/contracts/AssetTransfersHandler.sol
# perl -0777 -i -pe 's/safeT/t/g' pkg/vault/contracts/Fees.sol