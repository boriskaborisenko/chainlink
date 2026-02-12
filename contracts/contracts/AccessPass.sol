// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPassRegistry} from "./interfaces/IPassRegistry.sol";

contract AccessPass {
    error AlreadyMinted();
    error NotEligible(uint8 reason);

    IPassRegistry public immutable registry;
    uint256 public immutable policyId;

    uint256 public totalMinted;
    mapping(address => bool) public hasMinted;

    event PassMinted(address indexed user, uint256 indexed tokenId);

    constructor(address registryAddress, uint256 policyId_) {
        registry = IPassRegistry(registryAddress);
        policyId = policyId_;
    }

    function mint() external returns (uint256 tokenId) {
        if (hasMinted[msg.sender]) {
            revert AlreadyMinted();
        }

        (bool ok, uint8 reason) = registry.verifyUser(msg.sender, policyId);
        if (!ok) {
            revert NotEligible(reason);
        }

        tokenId = totalMinted + 1;
        totalMinted = tokenId;
        hasMinted[msg.sender] = true;

        emit PassMinted(msg.sender, tokenId);
    }
}
