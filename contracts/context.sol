/**
 * Slither Found - Dead Code Warnings
 * _msgSender() is never used.
 */
/**
 * RUN SLITHER ON MULTIPLE CONTRACTS  - 
 * context.sol
 * test.sol
 *  SPDX license Identifier not provided - No License 
 * 
 * DEAD CODE - _msgSender() not used in the file
 * 
 * @command -  slither contracts/ --print human-summary
 * slither contracts/ --json report.json
 */

// SPDX-License-Identifier: MIT

pragma solidity 0.8.20;

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}