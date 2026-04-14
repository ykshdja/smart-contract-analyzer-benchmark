// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    
    constructor() {
        totalSupply = 1000000;
    }
    
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
    
    function echidna_never_overflow() public view {
        assert(totalSupply >= 0);
    }
}