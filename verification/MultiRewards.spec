using ERC20A as erc20

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

    // envfreeing MultiRewards functions
    isAllowlistedRewarder(address, address, address) envfree
    totalSupply(address) envfree
    balanceOf(address, address) envfree

    // envfreeing harness functions
    Harness_num_rewarders(address, address) returns uint256 envfree
    Harness_isReadyToDistribute(address, address, address) envfree
    Harness_getLastUpdateTime(address, address, address) envfree
    Harness_getRewardRate(address, address, address) envfree
    Harness_getRewardDuration(address, address, address) envfree
    Harness_getUnpaidRewards(address, address, address) envfree
    Harness_getPaidRewards(address, address, address, address) envfree
    Harness_getRewardPerTokenStored(address, address, address) envfree
    Harness_getRewardPeriodFinish(address, address, address) envfree

}

rule allowlist_is_forever {
    address pool_token;
    address reward_token;
    address rewarder;
    require isAllowlistedRewarder(pool_token, reward_token, rewarder);

    env e;
    calldataarg a;
    method f;
    f(e, a);

    bool allowlisted = isAllowlistedRewarder(pool_token, reward_token, rewarder);
    assert allowlisted, "there is no way to remove a rewarder from the allowlist";
}

rule allowlist_integrity {
    env e;
    address pool_token;
    address reward_token;
    address rewarder;
    allowlistRewarder(e, pool_token, reward_token, rewarder);

    bool allowlisted = isAllowlistedRewarder(pool_token, reward_token, rewarder);

    assert allowlisted, "allowlistRewarder did not work properly";
}


rule allowlist_mutators {
    address pool_token;
    address reward_token;
    address rewarder;
    bool init = isAllowlistedRewarder(pool_token, reward_token, rewarder);

    env e;
    calldataarg a;
    method f;
    f(e, a);

    bool fin = isAllowlistedRewarder(pool_token, reward_token, rewarder);

    assert fin != init => f.selector == allowlistRewarder(address, address, address).selector,
            "the only function that can mutate the allowlist is isAllowlistedRewarder";
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
    preserved unstake(address _, uint256 _, address _) with (env e) {
        require account == e.msg.sender;
    } 
    preserved exit(address[] _) with (env e) {
        require account == e.msg.sender;
    }
    preserved exitWithCallback(address[] _, address _, bytes _) with (env e) {
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

    assert (fin_balance < init_balance) => (f.selector == exit(address[]).selector || 
            f.selector == unstake(address,uint256,address).selector || 
            f.selector == exitWithCallback(address[],address,bytes).selector), 
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
                (f.selector == stake(address, uint256).selector || f.selector == stakeFor(address, uint256, address).selector
                || f.selector == stakeWithPermit(address,uint256,uint256,address,uint8,bytes32,bytes32).selector), 
            "an unexpcted reduction of balance of";
}

invariant future_rewards_never_applicable (env e, address pool_token, address rewarder, address reward_token)
    e.block.timestamp >= lastTimeRewardApplicable(e, pool_token, rewarder, reward_token)

invariant applicable_rewards_greater_equal_to_last_update_time (env e, address pool_token, address rewarder, address reward_token)
    lastTimeRewardApplicable(e, pool_token, rewarder, reward_token) >= Harness_getLastUpdateTime(pool_token, rewarder, reward_token) {
        preserved unstake(address _, uint256 _, address _) with (env e2) {
            require e2.block.timestamp == e.block.timestamp;
        }
        preserved stake(address _, uint256 _) with (env e2) {
            require e2.block.timestamp == e.block.timestamp;
        }
        preserved stakeFor(address _, uint256 _, address _) with (env e2) {
            require e2.block.timestamp == e.block.timestamp;
        }
        preserved stakeWithPermit(address _, uint256 _, uint256 _, address _, uint8 _, bytes32 _, bytes32 _) with (env e2) {
            require e2.block.timestamp == e.block.timestamp;
        }
        preserved getReward(address[] _) with (env e2) {
            require e2.block.timestamp == e.block.timestamp;
        }
        preserved exit(address[] _) with (env e2) {
            require e2.block.timestamp == e.block.timestamp;
        }
        preserved exitWithCallback(address[] _, address _, bytes _) with (env e2) {
            require e2.block.timestamp == e.block.timestamp;
        }
        preserved getRewardAsInternalBalance(address[] _) with (env e2) {
            require e2.block.timestamp == e.block.timestamp;
        }
        preserved getRewardWithCallback(address[] _, address _, bytes _) with (env e2) {
            require e2.block.timestamp == e.block.timestamp;
        }
        preserved notifyRewardAmount(address _, address _, uint256 _) with (env e2) {
            require e2.block.timestamp == e.block.timestamp;
        }
    } 

rule wasteless_stake {
    env e;
    address pool_token;
    address account;
    uint256 init_balance = balanceOf(pool_token, account);

    uint256 amount;
    stakeFor(e, pool_token, amount, account);
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

    stakeFor(e, staked_pool_token, x, account_staked);
    stakeFor(e, staked_pool_token, y, account_staked);

    uint256 first_balance = balanceOf(pool_checked, account_checked);

    stakeFor(e, staked_pool_token, sumXY, account_staked) at init_state;
    uint256 second_balance = balanceOf(pool_checked, account_checked);


    assert first_balance == second_balance, "stake is additive";
}

rule wasteless_unstake {
    address pool_token;
    address recipient;
    env e;
    uint256 init_balance = balanceOf(pool_token, e.msg.sender);

    uint256 amount;
    unstake(e, pool_token, amount, recipient);
    uint256 fin_balance = balanceOf(pool_token, e.msg.sender);

    assert fin_balance + amount == init_balance, "staked money cannot go to waste";
}

rule unstake_additivity {
    address staked_pool_token;
    address pool_checked;
    address account_checked;
    address recipient;
    env e;

    uint256 x;
    uint256 y;
    uint256 sumXY = x + y;

    storage init_state = lastStorage;

    unstake(e, staked_pool_token, x, recipient);
    unstake(e, staked_pool_token, y, recipient);

    uint256 first_balance = balanceOf(pool_checked, account_checked);

    unstake(e, staked_pool_token, sumXY, recipient) at init_state;
    uint256 second_balance = balanceOf(pool_checked, account_checked);


    assert first_balance == second_balance, "unstake is additive";
}

/////////////////////////// Airdrop rules //////////////////////////////////////////////////////////////////////

rule airdrop_doesnt_affect_balances {
    address pool_token;
    address account;
    uint256 init_balance = balanceOf(pool_token, account);

    // airdrop to the pool
    env e;
    address sender;
    require sender != currentContract;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(e, sender, currentContract, amount);

    uint256 fin_balance = balanceOf(pool_token, account);

    assert init_balance == fin_balance, "airdrop shouldn't affect the balance of any user in any token";
}

rule airdrop_doesnt_affect_total_supply_of_pool_tokens {
    address pool_token;
    uint256 init_balance = totalSupply(pool_token);

    // airdrop to the pool
    env e;
    address sender;
    require sender != currentContract;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(e, sender, currentContract, amount);

    uint256 fin_balance = totalSupply(pool_token);

    assert init_balance == fin_balance, "airdrop shouldn't affect the total supply of any pool token";
}

rule airdrop_doesnt_add_rewarders {
    address pool_token;
    address reward_token;
    uint256 init_num_rewards = Harness_num_rewarders(pool_token, reward_token);

    // airdrop to the pool
    env e;
    address sender;
    require sender != currentContract;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(e, sender, currentContract, amount);

    uint256 fin_num_rewards = Harness_num_rewarders(pool_token, reward_token);

    assert init_num_rewards == fin_num_rewards, "airdrop shouldn't add a rewarder";
}

rule airdrop_doesnt_grant_rewarder_privileges {
    address pool_token;
    address reward_token;
    address rewarder;
    bool init_privilege = Harness_isReadyToDistribute(pool_token, reward_token, rewarder);

    // airdrop to the pool
    env e;
    address sender;
    require sender != currentContract;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(e, sender, currentContract, amount);

    bool fin_privilege = Harness_isReadyToDistribute(pool_token, reward_token, rewarder);

    assert init_privilege == fin_privilege, "airdrop shouldn't change rewarder privileges";
}

rule airdrop_doesnt_update_time {
    address pool_token;
    address reward_token;
    address rewarder;
    uint256 init_last_update_time = Harness_getLastUpdateTime(pool_token, reward_token, rewarder);

    // airdrop to the pool
    env e;
    address sender;
    require sender != currentContract;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(e, sender, currentContract, amount);

    uint256 fin_last_update_time = Harness_getLastUpdateTime(pool_token, reward_token, rewarder);

    assert init_last_update_time == fin_last_update_time, "airdrop shouldn't change the last update time";
}

rule airdrop_doesnt_update_rate {
    address pool_token;
    address reward_token;
    address rewarder;
    uint256 init_rate = Harness_getRewardRate(pool_token, reward_token, rewarder);

    // airdrop to the pool
    env e;
    address sender;
    require sender != currentContract;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(e, sender, currentContract, amount);

    uint256 fin_rate = Harness_getRewardRate(pool_token, reward_token, rewarder);

    assert init_rate == fin_rate, "airdrop shouldn't change any reward rate";
}

rule airdrop_doesnt_update_duration {
    address pool_token;
    address reward_token;
    address rewarder;
    uint256 init_duration = Harness_getRewardDuration(pool_token, reward_token, rewarder);

    // airdrop to the pool
    env e;
    address sender;
    require sender != currentContract;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(e, sender, currentContract, amount);

    uint256 fin_duration = Harness_getRewardDuration(pool_token, reward_token, rewarder);

    assert init_duration == fin_duration, "airdrop shouldn't change any reward duration";
}

rule airdrop_doesnt_update_unpaid_rewards {
    address pool_token;
    address account;
    address reward_token;
    uint256 init_rewards = Harness_getUnpaidRewards(pool_token, account, reward_token);

    // airdrop to the pool
    env e;
    address sender;
    require sender != currentContract;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(e, sender, currentContract, amount);

    uint256 fin_rewards = Harness_getUnpaidRewards(pool_token, account, reward_token);

    assert init_rewards == fin_rewards, "airdrop shouldn't change unpaid rewards";
}

rule airdrop_doesnt_update_paid_rewards {
    address pool_token;
    address reward_token;
    address rewarder;
    address account;
    uint256 init_rewards = Harness_getPaidRewards(pool_token, rewarder, account, reward_token);

    // airdrop to the pool
    env e;
    address sender;
    require sender != currentContract;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(e, sender, currentContract, amount);

    uint256 fin_rewards = Harness_getPaidRewards(pool_token, rewarder, account, reward_token);

    assert init_rewards == fin_rewards, "airdrop shouldn't change paid rewards";
}

rule airdrop_doesnt_update_reward_per_token {
    address pool_token;
    address rewarder;
    address reward_token;
    uint256 init_ratio = Harness_getRewardPerTokenStored(pool_token, rewarder, reward_token);

    // airdrop to the pool
    env e;
    address sender;
    require sender != currentContract;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(e, sender, currentContract, amount);

    uint256 fin_ratio = Harness_getRewardPerTokenStored(pool_token, rewarder, reward_token);

    assert init_ratio == fin_ratio, "airdrop shouldn't change reward per token ratios";
}

rule airdrop_doesnt_update_reward_period_finish {
    address pool_token;
    address rewarder;
    address reward_token;
    uint256 init_finish = Harness_getRewardPeriodFinish(pool_token, rewarder, reward_token);

    // airdrop to the pool
    env e;
    address sender;
    require sender != currentContract;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(e, sender, currentContract, amount);

    uint256 fin_finish = Harness_getRewardPeriodFinish(pool_token, rewarder, reward_token);

    assert init_finish == fin_finish, "airdrop shouldn't change period finish of any rewards";
}
