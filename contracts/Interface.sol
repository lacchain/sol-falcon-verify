//SPDX-License-Identifier: APACHE2
pragma solidity ^0.7.0;

contract FalconInterface {
    function verify(
        bytes calldata signature,
        bytes calldata publicKey,
        bytes calldata message,
        address falconVerifier
    ) public returns (bool isValid) {
        (bool success, bytes memory verifies) = address(falconVerifier).call(
            abi.encodeWithSignature(
                "verify(bytes,bytes,bytes)",
                signature,
                publicKey,
                message
            )
        );
        require(success && verifies.length == 32, "Invalid signature");
        return verifies[31] == 0;
    }
}
