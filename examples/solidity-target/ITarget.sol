// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface ITarget {
    function ping(uint256 n) external returns (uint256);
}
