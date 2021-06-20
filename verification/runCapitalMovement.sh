certoraRun verification/AaveAssetManagerHarness.sol verification/ERC20.sol verification/MockAaveLendingPool.sol \
  --verify AaveAssetManagerHarness:verification/capitalMovements.spec \
  --solc solc7.6 \
  --optimistic_loop \
  --smt_timeout 300 \
  --staging \
  --msg "all capital movements with getAUM() instead of readAUM()"