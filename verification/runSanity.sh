certoraRun verification/AaveAssetManagerHarness.sol \
  --verify AaveAssetManagerHarness:verification/sanity.spec \
  --solc solc7.6 \
  --settings -t=300 \
  --staging \
  --msg "Asset Manager sanity, flat rebalance fee"
