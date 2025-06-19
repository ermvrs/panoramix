// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableContract {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }

    function withdraw() external returns (uint256) {
        require(value > 10, 'val wrong');
        uint256 amount = address(this).balance;
        payable(msg.sender).transfer(amount);

        return amount;
    }
}