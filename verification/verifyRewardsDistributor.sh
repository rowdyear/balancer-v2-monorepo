certoraRun verification/RewardsDistributorHarness.sol verification/ERC20A.sol verification/ERC20B.sol \
  --verify RewardsDistributorHarness:verification/MultiRewards.spec \
  --solc solc7.6 \
  --optimistic_loop \
  --smt_timeout 300 \
  --staging \
  --settings -postProcessCounterExamples=true \
  --msg "all rules"