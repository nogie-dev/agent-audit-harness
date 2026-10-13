// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Authority} from "./Authority.sol";

contract Vault is Authority {
    receive() external payable {}

    function releaseA(address payable recipient) external {
        recipient.transfer(address(this).balance);
    }

    function releaseB(address payable recipient) external ownerOnly {
        recipient.transfer(address(this).balance);
    }
}
