// SPDX-License-Identifier: agpl-3.0
pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

contract DummyERC20 {
    uint256 total_supply;
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowances;

    string public name;
    string public symbol;
    uint public decimals;

    function myAddress() public view returns (address) {
        return address(this);
    }

    function add(uint a, uint b) internal pure returns (uint256) {
        uint sum = a + b;
        require (sum >= a);
        return sum;
    }
    function sub(uint a, uint b) internal pure returns (uint256) {
        require (a >= b);
        return a - b;
    }

    function totalSupply() external view returns (uint256) {
        return total_supply;
    }
    function balanceOf(address account) external view returns (uint256) {
        return balances[account];
    }
    function transfer(address recipient, uint256 amount) external returns (bool) {
        balances[msg.sender] = sub(balances[msg.sender], amount);
        balances[recipient] = add(balances[recipient], amount);
        return true;
    }
    function allowance(address owner, address spender) external view returns (uint256) {
        return allowances[owner][spender];
    }
    function approve(address spender, uint256 amount) external returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool) {
        require(total_supply >= balances[sender] + balances[recipient]);
        balances[sender] = sub(balances[sender], amount);
        balances[recipient] = add(balances[recipient], amount);
        allowances[sender][msg.sender] = sub(allowances[sender][msg.sender], amount);
        return true;
    }
}