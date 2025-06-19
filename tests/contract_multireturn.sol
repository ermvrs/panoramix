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

    function deposit() external payable {
        require(msg.value > 1 ether, 'low deposit');
    }

    function canEndDifferent() external returns(uint128){
        if(value > 10) {
            return 5;
        } else if (value > 5 ) {
            return 2;
        } else {
            value = 2;
            return 1;
        }
    }
}