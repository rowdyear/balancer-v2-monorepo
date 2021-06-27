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
    totalSupply(address) envfree
    balanceOf(address, address) envfree

    // envfreeing harness functions
    Harness_num_whitelisters(address, address) returns uint256 envfree
    Harness_num_rewarders(address, address) returns uint256 envfree
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

rule add_reward_integrity {
    env e;
    address pool_token;
    address reward_token;
    uint256 duration;
    addReward(e, pool_token, reward_token, duration);

    require Harness_num_rewarders(pool_token, reward_token) > 0; // If the length is zero, we had an overflow

    assert isReadyToDistribute(pool_token, reward_token, e.msg.sender), "add reward integrity";
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

rule only_way_to_distribute_is_add_reward {
    address pool_token;
    address reward_token;
    address rewarder;
    require !isReadyToDistribute(pool_token, reward_token, rewarder);

    env e;
    calldataarg a;
    method f;
    f(e, a);

    bool can_distribute = isReadyToDistribute(pool_token, reward_token, rewarder);
    assert can_distribute => f.selector == addReward(address,address,uint256).selector, "The only way to distribute is by adding the reward first";
}

invariant tot_supp_more_than_balance_of(address pool, address account) totalSupply(pool) >= balanceOf(pool, account) {
    preserved unstake(address a, uint256 b) with (env e) {
        require balanceOf(pool, account) + balanceOf(pool, e.msg.sender) <= totalSupply(pool);
    } 
    preserved exit(address[] a) with (env e) {
        require balanceOf(pool, account) + balanceOf(pool, e.msg.sender) <= totalSupply(pool);
    } 
}