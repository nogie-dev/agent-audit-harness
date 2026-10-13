// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Guards {
    event Step(uint256 code);
    error Blocked();

    function step(uint256 code) internal { emit Step(code); }
    function value() internal pure returns (uint256) { return 10; }

    modifier outer() { step(1); _; step(2); }
    modifier twice() { step(3); _; step(4); _; step(5); }
    modifier gate(bool allowed) {
        if (allowed) { step(6); _; step(7); }
        else { step(8); }
    }
    modifier early(bool skip) { if (skip) return; _; step(9); }
    modifier guarded(bool allowed) { require(allowed); _; assert(allowed); }
    modifier reject(bool blocked) { if (blocked) revert Blocked(); _; }
    modifier constantSkip() { if (false) { _; } step(11); }
    modifier alwaysRevert() { require(false); _; }
    modifier withArgument(uint256 code) { step(code); _; step(code + 1); }
    modifier repeated(uint256 count) { for (uint256 i; i < count; ++i) { _; } }
    modifier onceLoop() { do { _; break; } while (true); }
    modifier continueLoop(bool skip) {
        for (uint256 i; i < 2; ++i) { if (skip) continue; _; break; }
    }
    modifier afterReturn(bool skip) { _; if (skip) return; _; }
    modifier shortCircuit(bool allowed) { if (allowed && value() == 10) { _; } }
    modifier opaque() { assembly { mstore(0, 1) } _; }
    modifier virtualGuard() virtual { _; }
}
