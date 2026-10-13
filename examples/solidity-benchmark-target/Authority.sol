// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Authority {
    address public owner;

    constructor() { owner = msg.sender; }

    modifier ownerOnly() {
        require(msg.sender == owner, "owner");
        _;
    }
}
