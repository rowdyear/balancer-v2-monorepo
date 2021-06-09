certoraRun pkg/asset-manager-utils/contracts/AaveATokenAssetManager.sol \
  --verify AaveATokenAssetManager:verification/sanity.spec \
  --solc solc7.6 \
  --settings -t=300 \
  --debug \
  --staging --msg "Asset Manager sanity, flat rebalance fee"
