~/Projects/EVMVerifier/scripts/certoraRun.py verification/RewardsDistributorHarness.sol verification/ERC20A.sol verification/ERC20B.sol \
  --verify RewardsDistributorHarness:verification/MultiRewards.spec \
  --solc solc7.6 \
  --optimistic_loop \
  --smt_timeout 300 \
  --settings -postProcessCounterExamples=true \
  --cloud \
  --msg "all rules"
