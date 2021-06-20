# fix imports
find . -type f -name "*.sol" -exec sed -i 's/@balancer-labs\/v2-/pkg\//g' {} +

# safeTransfers to transfers, safeTransferTo to transferTo
find . -type f -name "*.sol" -exec sed -i 's/safeT/t/g' {} +

# virtualizing functions
perl -0777 -i -pe 's/\) internal pure returns \(uint256\) {/\) internal view virtual returns \(uint256\) {/g' pkg/asset-manager-utils/contracts/RewardsAssetManager.sol

# removing irrelevant function
perl -0777 -i -pe 's/vault\.managePoolBalance\(ops\);//g' pkg/asset-manager-utils/contracts/RewardsAssetManager.sol

# private to internal
perl -0777 -i -pe 's/_capitalOut\(uint256 amount\) private {/_capitalOut\(uint256 amount\) internal {/g' pkg/asset-manager-utils/contracts/RewardsAssetManager.sol
perl -0777 -i -pe 's/_capitalIn\(uint256 amount\) private {/_capitalIn\(uint256 amount\) internal {/g' pkg/asset-manager-utils/contracts/RewardsAssetManager.sol