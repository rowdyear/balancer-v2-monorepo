using ERC20A as erc

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

    verify(bytes32[], bytes32, bytes32) => NONDET
    


    //envfreeing methods
    claimed(uint256, address) returns (bool) envfree
    erc.balanceOf(address) envfree;
    verifyClaim(address, uint256, uint256, bytes32[]) envfree;
    owner() returns address envfree;
}

rule no_double_claim {
    uint256 week;
    address liquidityProvider;
    require claimed(week, liquidityProvider);

    method f;
    env e;
    calldataarg a;
    f(e, a);

    assert claimed(week, liquidityProvider), "once a reward is claimed, it cannot be claimed again";
}

rule no_double_seed {
    env e;
    uint256 week;
    bytes32 root;
    uint256 amount;
    seedAllocations(e, week, root, amount);

    bytes32 root2;
    uint256 amount2;

    seedAllocations@withrevert(e, week, root, amount);

    assert lastReverted, "cannot seed the same week twice";
}

rule only_sender_can_profit {
    address user;
    uint256 init_balance = erc.balanceOf(user);

    method f;
    env e;
    calldataarg a;

    if (f.selector == seedAllocations(uint256,bytes32,uint256).selector) {
        require user != currentContract;  //In seed allocations, the current contract gains funds
    }

    f(e, a);

    uint256 fin_balance = erc.balanceOf(user);

    assert fin_balance > init_balance => user == e.msg.sender;
}

rule capped_gains {
    address user;
    uint256 init_balance = erc.balanceOf(user);

    env e;
    address liquidityProvider;
    uint256 week;
    uint256 claimedBalance;
    bytes32[] merkleProof;
    claimWeek(e, liquidityProvider, week, claimedBalance, merkleProof);

    uint256 fin_balance = erc.balanceOf(user);

    assert fin_balance - init_balance <= claimedBalance, "a user cannot profit more than the claimed balance";
}

rule only_owner_pays {
    address user;
    require user != owner() && user != currentContract;
    uint256 init_balance = erc.balanceOf(user);

    method f;
    env e;
    calldataarg a;
    f(e, a);

    uint256 fin_balance = erc.balanceOf(user);

    assert fin_balance >= init_balance, "MerkleRedeem cannot take money from anyone but the owner";
}

rule only_verified_claims_can_succeed {
    env e;
    address liquidityProvider;
    uint256 week;
    uint256 claimedBalance;
    bytes32[] merkleProof;

    bool verified = verifyClaim(liquidityProvider, week, claimedBalance, merkleProof);
    claimWeek@withrevert(e, liquidityProvider, week, claimedBalance, merkleProof);
    bool claimed = lastReverted;

    assert !lastReverted => verified;
}
