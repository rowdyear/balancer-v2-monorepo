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
    isRewardUinitilized(bytes32) returns bool envfree
    isRewardPending(bytes32) returns bool envfree
    isRewardStarted(bytes32) returns bool envfree
}

invariant legalRewardStatus(bytes32 rewardId) isRewardUinitilized(rewardId) || isRewardPending(rewardId) || isRewardStarted(rewardId)
