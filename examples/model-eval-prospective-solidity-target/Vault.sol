// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Access} from "./Access.sol";

contract Vault is Access {
    address payable public payout;

    constructor() { payout = payable(msg.sender); }

    function setPayout(address payable next) external {
        payout = next;
    }

    function setPayoutByOwner(address payable next) external onlyOwner {
        payout = next;
    }

    function release() external onlyOwner {
        payout.transfer(address(this).balance);
    }
}
