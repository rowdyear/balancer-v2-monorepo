certoraRun verification/SchedulerHarness.sol \
  --verify SchedulerHarness:verification/sanity.spec \
  --solc solc7.6 \
  --settings -t=300 \
  --staging \
  --msg "SchedulerHarness sanity"