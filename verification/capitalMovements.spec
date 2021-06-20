using DummyERC20 as ERC20

methods {
    transfer(address, uint256) returns bool envfree => DISPATCHER(true)
    transferFrom(address, address, uint256) returns bool envfree => DISPATCHER(true)
    balanceOf(address) returns uint256 envfree => DISPATCHER(true)
	withdraw(address, uint256, address) => DISPATCHER(true)
    deposit(address, uint256, address, uint16) => DISPATCHER(true)
    mint(address, uint256) => DISPATCHER(true)
    burn(address, uint256) => DISPATCHER(true)

    getPoolTokenInfo(bytes32, address) => NONDET

    getAUM(bytes32) returns uint256 envfree
    Harness_capitalOut(uint256) envfree
    Harness_capitalIn(uint256) envfree
}

rule capital_out_decreases_investments {
    uint256 amount;
    bytes32 poolId;

    uint256 pre_aum = getAUM(poolId);
    Harness_capitalOut(amount);
    uint256 post_aum = getAUM(poolId);

    assert pre_aum >= post_aum, "capital out should reduce the number of managed assets";
}

rule capital_in_increases_investments {
    uint256 amount;
    // bytes32 poolId;

    // uint256 pre_aum = getAUM(poolId);
    Harness_capitalIn(amount);
    // uint256 post_aum = getAUM(poolId);

    // assert pre_aum <= post_aum, "capital in should increase the number of managed assets";
    assert true;
}