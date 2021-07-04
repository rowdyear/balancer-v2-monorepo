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
    isWhitelistedRewarder(address, address, address) envfree
    totalSupply(address) envfree
    balanceOf(address, address) envfree

    // envfreeing harness functions
    Harness_num_whitelisters(address, address) returns uint256 envfree
    Harness_num_rewarders(address, address) returns uint256 envfree
    Harness_isReadyToDistribute(address, address, address) envfree
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
    env e;
    address pool_token;
    address reward_token;
    address rewarder;
    whitelistRewarder(e, pool_token, reward_token, rewarder);

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

    assert Harness_isReadyToDistribute(pool_token, reward_token, e.msg.sender), "add reward integrity";
}

rule is_ready_to_distribute_forever {
    address pool_token;
    address reward_token;
    address rewarder;
    require Harness_isReadyToDistribute(pool_token, reward_token, rewarder);

    env e;
    calldataarg a;
    method f;
    f(e, a);

    assert Harness_isReadyToDistribute(pool_token, reward_token, rewarder), "once a reward is added, it cannot be removed";
}

rule only_way_to_distribute_is_add_reward {
    address pool_token;
    address reward_token;
    address rewarder;
    require !Harness_isReadyToDistribute(pool_token, reward_token, rewarder);

    env e;
    calldataarg a;
    method f;
    f(e, a);

    bool can_distribute = Harness_isReadyToDistribute(pool_token, reward_token, rewarder);
    assert can_distribute => f.selector == addReward(address,address,uint256).selector, "The only way to distribute is by adding the reward first";
}

invariant tot_supp_more_than_balance_of(address pool, address account) totalSupply(pool) >= balanceOf(pool, account) {
    preserved unstake(address a, uint256 b) with (env e) {
        require account == e.msg.sender;
    } 
    preserved exit(address[] a) with (env e) {
        require account == e.msg.sender;
    }
}

rule reducing_balance_of {
    address pool_token;
    address account;
    uint256 init_balance = balanceOf(pool_token, account);

    env e;
    calldataarg a;
    method f;
    f(e, a);

    uint256 fin_balance = balanceOf(pool_token, account);

    assert (fin_balance < init_balance) => (f.selector == exit(address[]).selector || f.selector == unstake(address,uint256).selector), 
            "an unexpcted reduction of balance of";
}

rule increasing_balance_of {
    address pool_token;
    address account;
    uint256 init_balance = balanceOf(pool_token, account);

    env e;
    calldataarg a;
    method f;
    f(e, a);

    uint256 fin_balance = balanceOf(pool_token, account);

    assert (fin_balance > init_balance) => 
                (f.selector == stake(address, uint256).selector || f.selector == stake(address, uint256, address).selector
                || f.selector == stakeWithPermit(address,uint256,uint256,address,uint8,bytes32,bytes32).selector), 
            "an unexpcted reduction of balance of";
}

invariant future_rewards_never_applicable (env e, address pool_token, address rewarder, address reward_token)
    e.block.timestamp >= lastTimeRewardApplicable(e, pool_token, rewarder, reward_token)

rule wasteless_stake {
    env e;
    address pool_token;
    address account;
    uint256 init_balance = balanceOf(pool_token, account);

    uint256 amount;
    stake(e, pool_token, amount, account);
    uint256 fin_balance = balanceOf(pool_token, account);

    assert fin_balance - init_balance == amount, "staked money cannot go to waste";
}

rule stake_additivity {
    env e;
    address staked_pool_token;
    address account_staked;
    address pool_checked;
    address account_checked;

    uint256 x;
    uint256 y;
    uint256 sumXY = x + y;

    storage init_state = lastStorage;

    stake(e, staked_pool_token, x, account_staked);
    stake(e, staked_pool_token, y, account_staked);

    uint256 first_balance = balanceOf(pool_checked, account_checked);

    stake(e, staked_pool_token, sumXY, account_staked) at init_state;
    uint256 second_balance = balanceOf(pool_checked, account_checked);


    assert first_balance == second_balance, "stake is additive";
}

rule wasteless_unstake {
    address pool_token;
    env e;
    uint256 init_balance = balanceOf(pool_token, e.msg.sender);

    uint256 amount;
    unstake(e, pool_token, amount);
    uint256 fin_balance = balanceOf(pool_token, e.msg.sender);

    assert fin_balance + amount == init_balance, "staked money cannot go to waste";
}

rule unstake_additivity {
    address staked_pool_token;
    address pool_checked;
    address account_checked;
    env e;

    uint256 x;
    uint256 y;
    uint256 sumXY = x + y;

    storage init_state = lastStorage;

    unstake(e, staked_pool_token, x);
    unstake(e, staked_pool_token, y);

    uint256 first_balance = balanceOf(pool_checked, account_checked);

    unstake(e, staked_pool_token, sumXY) at init_state;
    uint256 second_balance = balanceOf(pool_checked, account_checked);


    assert first_balance == second_balance, "unstake is additive";
}
