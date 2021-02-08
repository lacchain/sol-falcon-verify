
/* ====================================================================
 * Falcon Error codes:
 *    FALCON_ERR_SUCCESS  ( 0) : Call is successful
 *    FALCON_ERR_RANDOM   (-1) : Library tries to use an OS-provided RNG, but either none is supported, or that RNG fails.
 *    FALCON_ERR_SIZE     (-2) : A buffer has been provided to the library but is too small to receive the intended value.
 *    FALCON_ERR_FORMAT   (-3) : Decoding of an external object (public key, private key, signature) fails.
 *    FALCON_ERR_BADSIG   (-4) : Error verifying a signature. The signature is validly encoded, but its value does not match the provided message and public key.
 *    FALCON_ERR_BADARG   (-5) : A provided parameter is not in a valid range.
 *    FALCON_ERR_INTERNAL (-6) : Some internal computation failed.
 * In the interest of forward compatibility, callers should be prepared to receive additional error codes not included in the list below.
**********************************************************************/
const FALCON_ERR_SUCCESS  = 0;
const FALCON_ERR_RANDOM   = -1;
const FALCON_ERR_SIZE     = -2;
const FALCON_ERR_FORMAT   = -3;
const FALCON_ERR_BADSIG   = -4;
const FALCON_ERR_BADARG   = -5;
const FALCON_ERR_INTERNAL = -6;
var FALCON_ERR_Description = [ "FALCON_ERR_SUCCESS",
                               "FALCON_ERR_RANDOM",
                               "FALCON_ERR_SIZE",
                               "FALCON_ERR_FORMAT",
                               "FALCON_ERR_BADSIG",
                               "FALCON_ERR_BADARG",
                               "FALCON_ERR_INTERNAL" ];
var FALCON_ERR_LongDescription = [ "FALCON_ERR_SUCCESS (0) - All good",
                               "FALCON_ERR_RANDOM (-1) - Failed to acquire randomness from RNG",
                               "FALCON_ERR_SIZE (-2) - Buffer too small",
                               "FALCON_ERR_FORMAT (-3) - Failed to decode object (e.g. publicKey, privateKey or signature)",
                               "FALCON_ERR_BADSIG (-4) - Failed to verify Signature",
                               "FALCON_ERR_BADARG (-5) - Parameter invalid or out-of-range",
                               "FALCON_ERR_INTERNAL (-6) - Internal computation failure" ];

// Signature formats
const FALCON_SIG_INFERRED   = 0; // Signature format is inferred from the signature header byte; In this case, the signature is malleable (since a signature value can be transcoded to other formats).
const FALCON_SIG_COMPRESSED = 1; // Variable-size signature. This format produces the most compact signatures on average, but the signature size may vary depending on private key, signed data, and random seed.
const FALCON_SIG_PADDED     = 2; // Fixed-size signature. Same as compressed, but includes padding to a known fixed size (FALCON_SIG_PADDED_SIZE).
                                 // With this format, the signature generation loops until an appropriate signature size is achieved (such looping is uncommon) and adds the padding bytes;
                                 // the verification functions check the presence and contents of the padding bytes.
const FALCON_SIG_CT         = 3; // Fixed-size format amenable to constant-time implementation. All formats allow constant-time code with regard to the private key;
                                 // the 'CT' format also prevents information about the signature value and the signed data hash to leak through timing-based side channels (this feature is rarely needed).
const FALCON_SIG_INVALID    = 4;

module.exports = {
    FALCON_ERR_SUCCESS,
    FALCON_ERR_RANDOM,
    FALCON_ERR_SIZE,
    FALCON_ERR_FORMAT,
    FALCON_ERR_BADSIG,
    FALCON_ERR_BADARG,
    FALCON_ERR_INTERNAL,
    FALCON_ERR_Description,
    FALCON_ERR_LongDescription,
    FALCON_SIG_INFERRED,
    FALCON_SIG_COMPRESSED,
    FALCON_SIG_PADDED,
    FALCON_SIG_CT,
    FALCON_SIG_INVALID
};
