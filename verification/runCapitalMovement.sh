certoraRun verification/AaveAssetManagerHarness.sol verification/ERC20A.sol verification/ERC20B.sol verification/MockAaveLendingPool.sol \
  --verify AaveAssetManagerHarness:verification/capitalMovements.spec \
  --solc solc7.6 \
  --optimistic_loop \
  --smt_timeout 300 \
  --staging \
  --msg "capital movements make sense"