// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPassRegistry {
    function verifyUser(address user, uint256 policyId) external view returns (bool ok, uint8 reason);
}
