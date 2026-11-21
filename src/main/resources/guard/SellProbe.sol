// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
}

/**
 * Soheil Guard's sale test. Never deployed: the server places this code at a fresh address with an eth_call state
 * override (with some native coin for the test) and calls run() once. Nothing is signed or sent; the chain only
 * computes what would happen.
 *
 * It buys the token through a router, moves a little of it to another address, then sells part of it back through a
 * router, and reports how far it got and the amounts that arrived:
 *   stage 0 = the buy failed, 1 = moving the token failed, 2 = approving the router failed,
 *   3 = the buy delivered too little to go on, 4 = the sale failed, 5 = everything went through.
 *
 * Compiled with solc 0.8.24 (optimizer on, 200 runs, viaIR, evmVersion paris); the runtime bytecode is SellProbe.bin.
 */
contract SellProbe {
    function run(
        address token,
        address buyRouter,
        bytes calldata buyData,
        uint256 buyValue,
        address other,
        uint256 moveAmount,
        address sellRouter,
        uint256 sellAmount,
        bytes calldata sellData
    ) external returns (uint256 stage, uint256 received, uint256 moved, uint256 nativeOut) {
        uint256 before = IERC20(token).balanceOf(address(this));
        (bool ok,) = buyRouter.call{value: buyValue}(buyData);
        if (!ok) return (0, 0, 0, 0);
        uint256 afterBuy = IERC20(token).balanceOf(address(this));
        received = afterBuy > before ? afterBuy - before : 0;
        if (received < moveAmount + sellAmount) return (3, received, 0, 0);

        uint256 otherBefore = IERC20(token).balanceOf(other);
        (ok,) = token.call(abi.encodeWithSelector(0xa9059cbb, other, moveAmount));
        if (!ok) return (1, received, 0, 0);
        uint256 otherAfter = IERC20(token).balanceOf(other);
        moved = otherAfter > otherBefore ? otherAfter - otherBefore : 0;

        (ok,) = token.call(abi.encodeWithSelector(0x095ea7b3, sellRouter, type(uint256).max));
        if (!ok) return (2, received, moved, 0);

        uint256 nativeBefore = address(this).balance;
        (ok,) = sellRouter.call(sellData);
        if (!ok) return (4, received, moved, 0);
        nativeOut = address(this).balance - nativeBefore;
        return (5, received, moved, nativeOut);
    }

    receive() external payable {}
}
