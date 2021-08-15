~/Projects/EVMVerifier/scripts/certoraRun.py verification/HarnessMerkle.sol verification/ERC20A.sol verification/ERC20B.sol \
  --verify HarnessMerkle:verification/MerkleRedeem.spec \
  --solc solc7.6 \
  --optimistic_loop \
  --smt_timeout 300 \
  --settings -postProcessCounterExamples=true \
  --cloud \
  --msg "first rule of merkleredeem"
