certoraRun verification/InvestmentPoolHarness.sol \
  --verify InvestmentPoolHarness:verification/sanity.spec \
  --solc solc7.6 \
  --settings -t=300 \
  --staging \
  --debug \
  --msg "InvestmentPoolHarness sanity"