using MockAaveLendingPool as pool

methods {
    transfer(address, uint256) returns bool envfree => DISPATCHER(true)
    transferFrom(address, address, uint256) returns bool envfree => DISPATCHER(true)
    balanceOf(address) returns uint256 envfree => DISPATCHER(true)
	withdraw(address, uint256, address) => DISPATCHER(true)
    deposit(address, uint256, address, uint16) => DISPATCHER(true)
    mint(address, uint256) => DISPATCHER(true)
    burn(address, uint256) => DISPATCHER(true)

    0x3111e7b3 => NONDET  // IAaveIncentivesController.claimRewards
    notifyRewardAmount(address, address, uint256) => NONDET
    getPoolTokenInfo(bytes32, address) => NONDET

    getAUM(bytes32) returns uint256 envfree
    Harness_capitalOut(uint256) envfree
    Harness_capitalIn(uint256) envfree
    maxInvestableBalance(bytes32) envfree
    Harness_getTargetPercentage() envfree
    Harness_getUpperCriticalPercentage() envfree
    Harness_getLowerCriticalPercentage() envfree
    rebalance(bytes32, bool) envfree
    aToken() returns address envfree
    pool.aum_token() returns address envfree
    initialise(bytes32, address) envfree
    Harness_getMaxTargetInvestment() envfree
    Harness_getConf() returns (uint256, uint256, uint256) envfree
}

// definition MAX_TARGET_PERCENTAGE() returns uint256 = 0.95e18;

function validState {
    require aToken() == pool.aum_token();
}

rule capital_out_decreases_investments {
    validState();
    uint256 amount;
    bytes32 poolId;

    uint256 pre_aum = getAUM(poolId);
    Harness_capitalOut(amount);
    uint256 post_aum = getAUM(poolId);

    assert pre_aum >= post_aum, "capital out should reduce the number of managed assets";
}

rule capital_in_increases_investments {
    validState();
    uint256 amount;
    bytes32 poolId;

    uint256 pre_aum = getAUM(poolId);
    Harness_capitalIn(amount);
    uint256 post_aum = getAUM(poolId);

    assert pre_aum <= post_aum, "capital in should increase the number of managed assets";
}

// Rule below uses mulDown...
// rule rebalance_works {
//     validState();
//     bytes32 poolId;
//     rebalance(poolId, true);
//     int256 max_inv_b = maxInvestableBalance(poolId);
//     assert max_inv_b == 0, "after rebalance, max investable balance should be zero";
// }

rule single_init {
    bytes32 pool_id;
    address distributor;
    initialise(pool_id, distributor);
    initialise@withrevert(pool_id, distributor);
    assert lastReverted;
}

rule only_rebalance_can_change_aum {
    bytes32 poolId;
    uint256 pre_aum = getAUM(poolId);
    env e;
    calldataarg a;
    method f;

    // Ignore harness functions
    require f.selector != Harness_capitalOut(uint256).selector;
    require f.selector != Harness_capitalIn(uint256).selector;

    f(e, a);
    uint256 post_aum = getAUM(poolId);
    assert pre_aum != post_aum => f.selector == rebalance(bytes32, bool).selector;
}

invariant target_percentage_less_than_95() Harness_getTargetPercentage() <= Harness_getMaxTargetInvestment()

invariant legal_config() Harness_getUpperCriticalPercentage() >= Harness_getTargetPercentage() && Harness_getTargetPercentage() >= Harness_getLowerCriticalPercentage()

rule only_set_config_changes_config {
    uint256 init_target_percentage = Harness_getTargetPercentage();
    uint256 init_upper_percentage = Harness_getUpperCriticalPercentage();
    uint256 init_lower_percentage = Harness_getLowerCriticalPercentage();

    env e;
    calldataarg a;
    method f;

    uint256 fin_target_percentage = Harness_getTargetPercentage();
    uint256 fin_upper_percentage = Harness_getUpperCriticalPercentage();
    uint256 fin_lower_percentage = Harness_getLowerCriticalPercentage();

    bool target_changed = (init_target_percentage != fin_target_percentage);
    bool upper_changed = (init_upper_percentage != fin_upper_percentage);
    bool lower_changed = (init_lower_percentage != fin_lower_percentage);
    bool conf_changed = target_changed || upper_changed || lower_changed;

    assert conf_changed => f.selector == setConfig(bytes32, bytes).selector;
}