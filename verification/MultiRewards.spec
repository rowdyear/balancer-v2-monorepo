methods {
    // ERC20 methods
    transfer(address, uint256) returns bool envfree => DISPATCHER(true)
    transferFrom(address, address, uint256) returns bool envfree => DISPATCHER(true)
    balanceOf(address) returns uint256 envfree => DISPATCHER(true)
	withdraw(address, uint256, address) => DISPATCHER(true)
    deposit(address, uint256, address, uint16) => DISPATCHER(true)
    mint(address, uint256) => DISPATCHER(true)
    burn(address, uint256) => DISPATCHER(true)
    approve(address, uint256) => DISPATCHER(true)

    // envfreeing MultiRewards functions
    whitelistRewarder(address, address, address) envfree
    isWhitelistedRewarder(address, address, address) envfree
    isReadyToDistribute(address, address, address) envfree

    // envfreeing harness functions
    Harness_num_whitelisters(address, address) returns uint256 envfree
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

rule whitelist_integrity {
    address pool_token;
    address reward_token;
    address rewarder;
    whitelistRewarder(pool_token, reward_token, rewarder);

    require Harness_num_whitelisters(pool_token, reward_token) > 0; // If the length is zero, we had an overflow

    bool whitelisted = isWhitelistedRewarder(pool_token, reward_token, rewarder);

    assert whitelisted, "whitelistRewarder did not work properly";
}


rule whitelist_mutators {
    address pool_token;
    address reward_token;
    address rewarder;
    bool init = isWhitelistedRewarder(pool_token, reward_token, rewarder);

    env e;
    calldataarg a;
    method f;
    f(e, a);

    bool fin = isWhitelistedRewarder(pool_token, reward_token, rewarder);

    assert fin != init => f.selector == whitelistRewarder(address, address, address).selector,
            "the only function that can mutate the whitelist is isWhitelistedRewarder";
}

rule is_ready_to_distribute_forever {
    address pool_token;
    address reward_token;
    address rewarder;
    require isReadyToDistribute(pool_token, reward_token, rewarder);

    env e;
    calldataarg a;
    method f;
    f(e, a);

    assert isReadyToDistribute(pool_token, reward_token, rewarder), "once a reward is added, it cannot be removed";
}