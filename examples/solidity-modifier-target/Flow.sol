// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Guards} from "./Guards.sol";

contract Flow is Guards {
    function combined() public outer twice { step(99); }
    function swapped() public twice outer { step(99); }
    function fourTimes() public twice twice { step(99); }
    function conditional(bool allowed) public gate(allowed) { step(99); }
    function skippedInner(bool skip) public outer early(skip) { step(99); }
    function checked(bool allowed) public guarded(allowed) { step(99); }
    function rejected(bool blocked) public reject(blocked) { step(99); }
    function omitted() public constantSkip { step(99); }
    function fails() public alwaysRevert { step(99); }
    function arguments() public twice withArgument(value()) { step(99); }
    function looped(uint256 count) public repeated(count) { step(99); }
    function once() public onceLoop { step(99); }
    function continued(bool skip) public continueLoop(skip) { step(99); }
    function partialReturn(bool skip) public outer afterReturn(skip) { step(99); }
    function returnsValue() public outer returns (uint256) { return 1; }
    function short(bool allowed) public shortCircuit(allowed) { step(99); }
    function assemblyBoundary() public opaque { step(99); }
    function unknown() public virtualGuard { step(99); }
}
