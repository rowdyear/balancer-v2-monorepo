certoraRun pkg/asset-manager-utils/contracts/AaveATokenAssetManager.sol \
  --verify AaveATokenAssetManager:verification/sanity.spec \
  --solc solc7.6 \
  --settings -t=300 \
  --cache balancer_sanity \
  --staging --msg "Asset Manager sanity"
