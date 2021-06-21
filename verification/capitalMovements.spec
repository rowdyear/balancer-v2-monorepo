using MockAaveLendingPool as pool

methods {
    transfer(address, uint256) returns bool envfree => DISPATCHER(true)
    transferFrom(address, address, uint256) returns bool envfree => DISPATCHER(true)
    balanceOf(address) returns uint256 envfree => DISPATCHER(true)
	withdraw(address, uint256, address) => DISPATCHER(true)
    deposit(address, uint256, address, uint16) => DISPATCHER(true)
    mint(address, uint256) => DISPATCHER(true)
    burn(address, uint256) => DISPATCHER(true)

    getPoolTokenInfo(bytes32, address) => NONDET

    getAUM(bytes32) returns uint256 envfree
    Harness_capitalOut(uint256) envfree
    Harness_capitalIn(uint256) envfree
    maxInvestableBalance(bytes32) envfree
    rebalance(bytes32, bool) envfree
    aToken() returns address envfree
    pool.aum_token() returns address envfree
}

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