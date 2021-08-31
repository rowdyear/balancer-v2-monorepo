using ERC20A as erc20

methods {
    // Dispatching ERC20 methods
    transfer(address, uint256) returns bool => DISPATCHER(true)
    transferFrom(address, address, uint256) returns bool => DISPATCHER(true)
    balanceOf(address) returns uint256 => DISPATCHER(true)
	withdraw(address, uint256, address) => DISPATCHER(true)
    deposit(address, uint256, address, uint16) => DISPATCHER(true)
    mint(address, uint256) => DISPATCHER(true)
    burn(address, uint256) => DISPATCHER(true)
    approve(address, uint256) => DISPATCHER(true)
    erc20.balanceOf(address) returns uint256 envfree

    getRewardId(address, address, address, uint256) returns bytes32 => CONSTANT

    // Dispatching Multirewards methods
    notifyRewardAmount(address, address, uint256, address) => DISPATCHER(true)
    isAllowlistedRewarder(address, address, address) returns bool => DISPATCHER(true)

    // envfreeing RewardsScheduler functions


    // envfreeing SchedulerHarness functions
    Harness_isRewardUinitilized(bytes32) returns bool envfree
    Harness_isRewardPending(bytes32) returns bool envfree
    Harness_isRewardStarted(bytes32) returns bool envfree
    Harness_getRewardStartTime(bytes32) returns uint256 envfree
}

invariant legalRewardStatus(bytes32 rewardId) Harness_isRewardUinitilized(rewardId) || Harness_isRewardPending(rewardId) || Harness_isRewardStarted(rewardId)

rule uninitializedToPending {
    bytes32 rewardId;
    require Harness_isRewardUinitilized(rewardId);

    method f;
    env e;
    calldataarg a;
    f(e, a);

    bool still_uninitialized = Harness_isRewardUinitilized(rewardId);
    bool now_pending = Harness_isRewardPending(rewardId);

    assert still_uninitialized || (now_pending && f.selector == scheduleReward(address, address, uint256, uint256).selector), "integrity of uinitialized passes";
}

rule pendingToStarted {
    bytes32 rewardId;
    require Harness_isRewardPending(rewardId);

    method f;
    require f.selector != Harness_startReward(bytes32).selector;
    env e;
    calldataarg a;
    f(e, a);

    bool still_pending = Harness_isRewardPending(rewardId);
    bool now_started = Harness_isRewardStarted(rewardId);

    assert still_pending || (now_started && f.selector == startRewards(bytes32[]).selector), "integrity of pending rewards";
}

rule startedForever {
    bytes32 rewardId;
    require Harness_isRewardStarted(rewardId);

    method f;
    env e;
    calldataarg a;
    f(e, a);

    assert Harness_isRewardStarted(rewardId), "A Started reward cannot be stopped";
}

rule rewards_are_started_in_the_past {
    bytes32 rewardId;

    env e;
    require Harness_isRewardStarted(rewardId) => Harness_getRewardStartTime(rewardId) <= e.block.timestamp;

    method f;
    calldataarg a;
    f(e, a);
    
    assert Harness_isRewardStarted(rewardId) => Harness_getRewardStartTime(rewardId) <= e.block.timestamp;
}

rule no_double_sched {
    env e;
    require e.msg.sender != currentContract;
    address pool;
    address token;
    uint256 amount_a;
    uint256 start_time;
    bytes32 rewardId_a = scheduleReward(e, pool, token, amount_a, start_time);

    uint256 amount_b;
    bytes32 rewardId_b = scheduleReward@withrevert(e, pool, token, amount_b, start_time);

    assert lastReverted, "cannot schedule the same reward twice";
}

rule sched_requires_payment {
    uint256 init_balance = erc20.balanceOf(currentContract);

    env e;
    require e.msg.sender != currentContract;
    address pool;
    uint256 amount;
    uint256 time;
    scheduleReward(e, pool, erc20, amount, time);

    uint256 fin_balance = erc20.balanceOf(currentContract);
    assert fin_balance - init_balance == amount, "cannot schedule a reward without paying";
}

rule no_double_start_reward {
    env e;
    bytes32 rewardId;
    Harness_startReward(e, rewardId);

    Harness_startReward@withrevert(e, rewardId);

    assert lastReverted, "cannot start the same reward twice";
}

rule sched_then_atarting_reward_nets_zero_balance {
    uint256 init_balance = erc20.balanceOf(currentContract);

    env e;
    require e.msg.sender != currentContract;
    address pool;
    uint256 amount;
    uint256 time;
    bytes32 rewardId = scheduleReward(e, pool, erc20, amount, time);

    env e2;
    Harness_startReward(e2, rewardId);

    uint256 fin_balance = erc20.balanceOf(currentContract);
    assert fin_balance == init_balance, "scheduling then claiming a reward should not affect the balance of the scheduler";
}