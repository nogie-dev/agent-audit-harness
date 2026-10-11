// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
abstract contract Base {
    address public owner;
    uint256 public value;
    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }
    function helper(uint256 n) internal pure returns (uint256) { return n + 1; }
    function hook(uint256 n) internal virtual returns (uint256) { return helper(n); }
    function viaVirtual(uint256 n) internal returns (uint256) { return hook(n); }
}
