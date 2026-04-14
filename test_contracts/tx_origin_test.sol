// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TxOriginTest {
    function withdraw() public {
        require(tx.origin == msg.sender); // This SHOULD be detected as tx_origin
        msg.sender.transfer(1 ether);
    }
}
