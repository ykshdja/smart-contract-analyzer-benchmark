/**
1. the reentrancy vulnerability
-external call allows an attacker to repeatedly
re-enter a function before the previous 
execution finishes, manipulating contract state

*/

/**
 * MULTIPLE CONTRACT SCAN on TEST.sol
 * Detector:
arbitrary-send-eth - Contract sends ETH to caller address.

 */



// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Vulnerable {
    uint public balance;

    function deposit() public payable {
        balance += msg.value;
    }

    function withdraw(uint amount) public {
    require(balance >= amount);

    balance -= amount;   // update state first
    payable(msg.sender).transfer(amount);
}
}