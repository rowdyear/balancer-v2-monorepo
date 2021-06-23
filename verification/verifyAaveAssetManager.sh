certoraRun verification/AaveAssetManagerHarness.sol verification/ERC20A.sol verification/ERC20B.sol verification/MockAaveLendingPool.sol \
  --verify AaveAssetManagerHarness:verification/AaveAssetManager.spec \
  --solc solc7.6 \
  --optimistic_loop \
  --smt_timeout 300 \
  --staging \
  --settings -postProcessCounterExamples=true \
  --msg "all rules"