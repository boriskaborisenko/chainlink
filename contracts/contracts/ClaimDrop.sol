// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPassRegistry} from "./interfaces/IPassRegistry.sol";

contract ClaimDrop {
    error AlreadyClaimed();
    error NotEligible(uint8 reason);

    IPassRegistry public immutable registry;
    uint256 public immutable policyId;
    uint256 public immutable claimAmount;

    mapping(address => bool) public claimed;

    event Claimed(address indexed user, uint256 amount);

    constructor(address registryAddress, uint256 policyId_, uint256 claimAmount_) {
        registry = IPassRegistry(registryAddress);
        policyId = policyId_;
        claimAmount = claimAmount_;
    }

    function claim() external {
        if (claimed[msg.sender]) {
            revert AlreadyClaimed();
        }

        (bool ok, uint8 reason) = registry.verifyUser(msg.sender, policyId);
        if (!ok) {
            revert NotEligible(reason);
        }

        claimed[msg.sender] = true;
        emit Claimed(msg.sender, claimAmount);
    }

    function canClaim(address user) external view returns (bool ok, uint8 reason) {
        if (claimed[user]) {
            return (false, 255);
        }

        return registry.verifyUser(user, policyId);
    }
}
