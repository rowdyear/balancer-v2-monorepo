

methods {
    // ERC20 methods
    transfer(address, uint256) returns bool => DISPATCHER(true)
    transferFrom(address, address, uint256) returns bool => DISPATCHER(true)
    balanceOf(address) returns uint256 => DISPATCHER(true)
	withdraw(address, uint256, address) => DISPATCHER(true)
    deposit(address, uint256, address, uint16) => DISPATCHER(true)
    mint(address, uint256) => DISPATCHER(true)
    burn(address, uint256) => DISPATCHER(true)
    approve(address, uint256) => DISPATCHER(true)

    //envfreeing methods
    claimed(uint256, address) returns (bool) envfree
}

rule no_double_claim {
    uint256 week;
    address liquidityProvider;
    require claimed(week, liquidityProvider);

    method f;
    env e;
    calldataarg a;
    f(e, a);

    assert claimed(week, liquidityProvider), "once a reward is claimed, it cannot be claimed again";
}