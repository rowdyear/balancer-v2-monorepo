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

    erc20.transferFrom(address, address, uint256) envfree
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

rule airdrop_doesnt_affect_balances {
    address pool_token;
    address account;
    uint256 init_balance = balanceOf(pool_token, account);

    // airdrop to the pool
    address sender;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(sender, currentContract, amount);

    uint256 fin_balance = balanceOf(pool_token, account);

    assert init_balance == fin_balance, "airdrop shouldn't affect the balance of any user in any token";
}

rule airdrop_doesnt_affect_total_supply_of_pool_tokens {
    address pool_token;
    uint256 init_balance = totalSupply(pool_token);

    // airdrop to the pool
    address sender;
    uint256 amount;
    require amount > 0;
    erc20.transferFrom(sender, currentContract, amount);

    uint256 fin_balance = totalSupply(pool_token);

    assert init_balance == fin_balance, "airdrop shouldn't affect the total supply of any pool token";
}
