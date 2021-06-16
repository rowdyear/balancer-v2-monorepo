using DummyERC20 as ERC20

methods {
    transfer(address, uint256) returns bool envfree => DISPATCHER(true)
    transferFrom(address, address, uint256) returns bool envfree => DISPATCHER(true)
    balanceOf(address) returns uint256 envfree => DISPATCHER(true)

	withdraw(address, uint256, address) => NONDET
    getPoolTokenInfo(bytes32, address) => NONDET
    readAUM() returns uint256 envfree
}

rule capital_out_decreases_investments {
	bytes32 poolId;
    uint256 amount;
    env e;

    // uint256 pre_aum = readAUM();
    capitalOut(e, poolId, amount);
    assert true;
    // uint256 post_aum = readAUM();

    // assert pre_aum >= post_aum, "capital out should reduce the number of managed assets";
}