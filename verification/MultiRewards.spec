methods {
    // ERC20 methods
    transfer(address, uint256) returns bool envfree => DISPATCHER(true)
    transferFrom(address, address, uint256) returns bool envfree => DISPATCHER(true)
    balanceOf(address) returns uint256 envfree => DISPATCHER(true)
	withdraw(address, uint256, address) => DISPATCHER(true)
    deposit(address, uint256, address, uint16) => DISPATCHER(true)
    mint(address, uint256) => DISPATCHER(true)
    burn(address, uint256) => DISPATCHER(true)

    // envfreeing MultiRewards functions
    whitelistRewarder(address, address, address) envfree
    isWhitelistedRewarder(address, address, address) envfree
}

rule whitelist_is_forever {
    address pool_token;
    address reward_token;
    address rewarder;
    require isWhitelistedRewarder(pool_token, reward_token, rewarder);

    env e;
    calldataarg a;
    method f;
    f(e, a);

    bool whitelisted = isWhitelistedRewarder(pool_token, reward_token, rewarder);
    assert whitelisted, "there is no way to remove a rewarder from the whitelist";
}

rule whitelist_integrity() {
    address pool_token;
    address reward_token;
    address rewarder;
    whitelistRewarder(pool_token, reward_token, rewarder);

    bool whitelisted = isWhitelistedRewarder(pool_token, reward_token, rewarder);

    assert whitelisted, "whitelistRewarder did not work properly";
}