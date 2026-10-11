// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library Ops {
    function bump(uint256 n) internal pure returns (uint256) { return n + 1; }
    function linked(uint256 n) public pure returns (uint256) { return n + 2; }
}
