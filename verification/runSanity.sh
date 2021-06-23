certoraRun pkg/distributors/contracts/MultiRewards.sol \
  --verify MultiRewards:verification/sanity.spec \
  --solc solc7.6 \
  --settings -t=300 \
  --staging \
  --msg "Multi Rewards sanity"
