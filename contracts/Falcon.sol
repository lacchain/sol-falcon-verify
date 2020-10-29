// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.7.0;

contract Falcon {

  /* ==================================================================== */
  /*
   * Error codes.
   *
   * Most functions in this API that may fail for some reason return an
   * 'int' value which will be 0 on success, or a negative error code.
   * The macros below define the error codes. In the interest of forward
   * compatibility, callers should be prepared to receive additional error
   * codes not included in the list below.
   */

  /*
   * FALCON_ERR_FORMAT is returned when decoding of an external object
   * (public key, private key, signature) fails.
   */
  int8 constant FALCON_ERR_FORMAT = -3;

  /*
   * FALCON_ERR_BADSIG is returned when verifying a signature, the signature
   * is validly encoded, but its value does not match the provided message
   * and public key.
   */
  int8 constant FALCON_ERR_BADSIG = -4;


  /*
   * FALCON_ERR_BADARG is returned when a provided parameter is not in
   * a valid range.
   */
  int8 constant FALCON_ERR_BADARG = -5;

  /* ==================================================================== */
  /*
   * Signature formats.
   */

  /*
   * Variable-size signature. This format produces the most compact
   * signatures on average, but the signature size may vary depending
   * on private key, signed data, and random seed.
   */
  uint8 constant FALCON_SIG_COMPRESSED = 1;

  /*
   * Fixed-size signature. This format produces is equivalent to the
   * "compressed" format, but includes padding to a known fixed size
   * (specified by FALCON_SIG_PADDED_SIZE). With this format, the
   * signature generation loops until an appropriate signature size is
   * achieved (such looping is uncommon) and adds the padding bytes;
   * the verification functions check the presence and contents of the
   * padding bytes.
   */
  uint8 constant FALCON_SIG_PADDED = 2;

  /*
   * Fixed-size format amenable to constant-time implementation. All formats
   * allow constant-time code with regard to the private key; the 'CT'
   * format of signature also prevents information about the signature value
   * and the signed data hash to leak through timing-based side channels
   * (this feature is rarely needed).
   */
  uint8 constant FALCON_SIG_CT = 3;

  function verify(bytes memory signature, uint8 signatureType, bytes memory pubKey, bytes memory data) public pure returns (int8) {
    int8 r = start(signature);
    if (r < 0) {
      return r;
    }
    return finish(signature, signatureType, pubKey, keccak256(data));
  }

  function start(bytes memory signature) private pure returns (int8) {
    if (signature.length < 41) {
      return FALCON_ERR_FORMAT;
    }
    return 0;
  }

  function finish(bytes memory signature, uint8 signatureType, bytes memory pubKey, bytes32 dataHash) private pure returns (int8) {
    if (pubKey.length == 0) {
      return FALCON_ERR_FORMAT;
    }

    if ((pubKey[0] & 0xF0) != 0x00) {
      return FALCON_ERR_FORMAT;
    }

    uint8 logn = uint8(pubKey[0] & 0x0F);
    if (logn < 1 || logn > 10) {
      return FALCON_ERR_FORMAT;
    }

    if (uint8(signature[0] & 0x0F) != logn) {
      return FALCON_ERR_BADSIG;
    }

    uint8 ct = 0;
    if (signatureType == 0) {
      byte inferredType = signature[0] & 0xF0;
      if (inferredType == 0x30 || inferredType == 0x50) {
        if (signature.length != signatureCtSize(logn)) {
          return FALCON_ERR_FORMAT;
        }
        ct = 1;
      } else {
        return FALCON_ERR_BADSIG;
      }
    } else if (signatureType == FALCON_SIG_COMPRESSED) {
    } else if (signatureType == FALCON_SIG_PADDED) {
    } else if (signatureType == FALCON_SIG_CT) {
    } else {
      return FALCON_ERR_BADARG;
    }
    return 0;
  }

  /*
   * Signature size (in bytes) when using the CT format. The size is exact.
   */
  function signatureCtSize(uint8 logn) public pure returns (uint16) {
    return ((uint16(3) << ((logn) - 1)) - ((logn) == 3?1:0) + 41);
  }
}
