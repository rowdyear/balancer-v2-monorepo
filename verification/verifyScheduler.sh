~/Projects/EVMVerifier/scripts/certoraRun.py verification/SchedulerHarness.sol \
    verification/ERC20A.sol verification/ERC20B.sol pkg/distributors/contracts/MultiRewards.sol \
  --verify SchedulerHarness:verification/Scheduler.spec \
  --solc solc7.6 \
  --optimistic_loop \
  --smt_timeout 600 \
  --settings -postProcessCounterExamples=true \
  --cloud \
  --msg "all rules"
