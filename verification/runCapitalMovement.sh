certoraRun verification/AaveAssetManagerHarness.sol verification/ERC20.sol verification/MockAaveLendingPool.sol \
  --verify AaveAssetManagerHarness:verification/capitalMovements.spec \
  --solc solc7.6 \
  --optimistic_loop \
  --rule_sanity \
  --rule capital_in_increases_investments \
  --smt_timeout 300 \
  --staging \
  --msg "rule capital_in_increases_investments sanity, only Harness_capitalIn no check for difference"