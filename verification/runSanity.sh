certoraRun verification/RewardsDistributorHarness.sol \
  --verify RewardsDistributorHarness:verification/sanity.spec \
  --solc solc7.6 \
  --settings -t=300 \
  --staging \
  --msg "RewardsDistributorHarness sanity"