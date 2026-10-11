// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Base} from "./Base.sol";
import {Ops} from "./Ops.sol";
import {ITarget} from "./ITarget.sol";
contract Wallet is Base {
    function entry(ITarget peer, address low, uint256 n) public onlyOwner returns (uint256) {
        uint256 v = Ops.bump(helper(n));
        stage(v);
        peer.ping{gas: 100000}(v);
        this.echo(v);
        Ops.linked(v);
        (bool ok,) = low.call("");
        require(ok);
        return v;
    }
    function stage(uint256 n) internal { value = n; }
    function echo(uint256 n) external pure returns (uint256) { return n; }
    function hook(uint256 n) internal override returns (uint256) { return super.hook(n) + 1; }
    function invokeVirtual(uint256 n) public returns (uint256) { return viaVirtual(n); }
    function dynamic(function(uint256) internal returns(uint256) cb, uint256 n) internal returns(uint256) {
        return cb(n);
    }
}
