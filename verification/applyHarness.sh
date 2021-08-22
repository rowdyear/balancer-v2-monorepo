# fix imports
find . -type f -name "*.sol" -exec sed -i 's/@balancer-labs\/v2-/pkg\//g' {} +

# safeTransfers to transfers, safeTransferTo to transferTo
find . -type f -name "*.sol" -exec sed -i 's/safeT/t/g' {} +
# The above line creates name collision with safeERC20.sol, so we do not import it anymore
perl -0777 -i -pe 's/import "pkg\/solidity-utils\/contracts\/openzeppelin\/SafeERC20\.sol";//g' pkg/distributors/contracts/MultiRewards.sol
perl -0777 -i -pe 's/using SafeERC20 for IERC20;//g' pkg/distributors/contracts/MultiRewards.sol
perl -0777 -i -pe 's/using SafeERC20 for IERC20;//g' pkg/distributors/contracts/MerkleRedeem.sol
perl -0777 -i -pe 's/using SafeERC20 for IERC20;//g' pkg/distributors/contracts/RewardsScheduler.sol

# virtualizing functions
perl -0777 -i -pe 's/\) internal pure returns \(uint256\) {/\) internal view virtual returns \(uint256\) {/g' pkg/asset-manager-utils/contracts/RewardsAssetManager.sol

# removing irrelevant functions
perl -0777 -i -pe 's/getVault\(\)\.managePoolBalance\(ops\);//g' pkg/asset-manager-utils/contracts/RewardsAssetManager.sol
perl -0777 -i -pe 's/getVault\(\)\.manageUserBalance\(ops\);//g' pkg/distributors/contracts/MultiRewards.sol
perl -0777 -i -pe 's/vault\.manageUserBalance\(ops\);//g' pkg/distributors/contracts/MerkleRedeem.sol
perl -0777 -i -pe 's/callbackContract\.callback\(callbackData\);//g' pkg/distributors/contracts/MultiRewards.sol
perl -0777 -i -pe 's/callbackContract\.distributorCallback\(callbackData\);//g' pkg/distributors/contracts/MerkleRedeem.sol

# private to internal
perl -0777 -i -pe 's/_capitalOut\(uint256 amount\) private {/_capitalOut\(uint256 amount\) internal {/g' pkg/asset-manager-utils/contracts/RewardsAssetManager.sol
perl -0777 -i -pe 's/_capitalIn\(uint256 amount\) private {/_capitalIn\(uint256 amount\) internal {/g' pkg/asset-manager-utils/contracts/RewardsAssetManager.sol
perl -0777 -i -pe 's/InvestmentConfig private _config/InvestmentConfig internal _config/g' pkg/asset-manager-utils/contracts/RewardsAssetManager.sol
perl -0777 -i -pe 's/private _allowlist/internal _allowlist/g' pkg/distributors/contracts/MultiRewards.sol
perl -0777 -i -pe 's/private _rewarders/internal _rewarders/g' pkg/distributors/contracts/MultiRewards.sol
perl -0777 -i -pe 's/private _balances/internal _balances/g' pkg/distributors/contracts/MultiRewards.sol
perl -0777 -i -pe 's/length\(AddressSet storage set\) internal view/length\(AddressSet storage set\) external view/g' pkg/solidity-utils/contracts/openzeppelin/EnumerableSet.sol

# external to public
perl -0777 -i -pe 's/claimWeeks\(address liquidityProvider, Claim\[\] memory claims\) external {/claimWeeks\(address liquidityProvider, Claim\[\] memory claims\) public {/g' pkg/distributors/contracts/MerkleRedeem.sol

# removing a "graceful failure" require
perl -0777 -i -pe 's/require\(amount > 0, "Cannot withdraw 0"\);//g' pkg/distributors/contracts/MultiRewards.sol
