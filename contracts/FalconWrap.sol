// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

import "./Falcon.sol";

contract FalconWrap is Falcon {
    function verify(
        bytes calldata signature,
        bytes calldata publicKey,
        bytes calldata message
    ) public returns (int16) {
        uint8 signatureType = (uint8(signature[0]) >> 5) & 0x03;
        return
            verify(
                signatureType,
                signature,
                uint16(signature.length),
                message,
                uint16(message.length),
                publicKey,
                uint16(publicKey.length)
            );
    }
}
