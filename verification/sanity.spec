methods {
	withdraw(address, uint256, address) => NONDET
}

rule sanity(method f) {
	env e;
	calldataarg arg;
	f(e, arg);
	assert false, "this method should have a non reverting path";
}