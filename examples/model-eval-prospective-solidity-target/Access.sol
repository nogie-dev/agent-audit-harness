// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Access {
    address internal owner;

    constructor() { owner = msg.sender; }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }
}
