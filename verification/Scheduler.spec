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