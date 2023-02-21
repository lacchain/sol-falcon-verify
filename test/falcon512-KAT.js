const assert = require('assert');
const hre = require("hardhat");
const fs = require('fs');
const readline = require('readline');
const Test = require('mocha/lib/test');

const falcConsts = require('./falcon_constants.js');

describe("Falcon", async () =>
{
    const suite = describe("falcon512-KAT - Known Answer Tests", async () =>
    {

      before(async () =>
      {
        const kats = await parseKats(fs.createReadStream('test/falcon512-KAT.rsp'));
        const Falcon = await hre.ethers.getContractFactory('Falcon')
        falconInstance = await Falcon.deploy();

        //kats.slice(0, 5).forEach(kat =>  // Tests 0,1,2,3,4
        kats.forEach(kat =>  // All Tests
        {
          suite.addTest(new Test(`KAT test ${kat.count}`, async() =>
          {
            let signatureType = falcConsts.FALCON_SIG_1_COMPRESSED; // FALCON_SIG_0_INFERRED, FALCON_SIG_1_COMPRESSED, FALCON_SIG_2_PADDED, FALCON_SIG_3_CT
            const msg   = Buffer.from(kat.msg, 'hex');
            const mlen  = parseInt(kat.mlen);
            const pk    = Buffer.from(kat.pk, 'hex');
            const pklen = pk.length;
            const sm    = Buffer.from(kat.sm, 'hex');
            const smlen = parseInt(kat.smlen);

            // Deconstruct KAT sm field which is in "3.11.6 NIST API" format
            const smSigLen     = sm.readInt16BE(0);                         // Convert a 2 byte BigEndian value to a number
            const smNonce      = sm.slice(2, 42);                           // Skip over the 2 bytes for the smSigLen
            const smMsg        = sm.slice(2 + 40, smlen-2-40-smSigLen);     // Not used - Should be identical to msg
            const smSig        = sm.slice(2 + 40 + mlen);                   // Skip 2 bytes for signatureSize + 40 bytes for nonce + mlen bytes for message.
            const smSigHdrByte = smSig.slice(0, 1);                         // Header Byte
            const smSigRaw     = smSig.slice(1);                            // Raw Signature

            // Construct Signature field to send to the contract which expects it in "3.11.3 Signatures" format
            var argSigHdrBuf = Buffer.from([0x39]);
            const argSig     = Buffer.concat([argSigHdrBuf, smNonce, smSigRaw]);
            const argSigLen  = argSigHdrBuf.length + smNonce.length + smSigRaw.length;

            //console.log("==> argSigHdrBuf[%d]: 0x%s", argSigHdrBuf.length, argSigHdrBuf.toString('hex'));
            //console.log("==> smSigRawLen = smlen(%d) - smSigLen.len(2) - nonceNen(40) - mlen(%d) - sigHdrByte(1) = %d [%d]",
            //                smlen, mlen,
            //                (smlen - 2 - 40 - mlen - 1),
            //                smSigRaw.length );
            //console.log("==> argSig[%d]: 0x%s", argSigLen, argSig.toString('hex'));

            if (1)
            {
                const contractReturn = await falconInstance.callStatic.verify(signatureType, Array.from(argSig), argSigLen, Array.from(msg), mlen, Array.from(pk), pklen);
                if (contractReturn != falcConsts.FALCON_ERR_SUCCESS)
                {
                	let ret = getFalconReturnValue(contractReturn);
                    let errorReasonCode = getReasonCode(contractReturn);
                    let errorStr = "ERROR: falcon.verify returned " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
                    console.log(errorStr);
                }
                const falconReturn = getFalconReturnValue(contractReturn);
                assert.equal(falconReturn, falcConsts.FALCON_ERR_SUCCESS, `${falcConsts.FALCON_ERR_LongDescription[Math.abs(falconReturn)]}`);
            }
            else
            {
                let expectedRet = falcConsts.FALCON_ERR_SUCCESS;
                const signature_array = argSig.toJSON().data;
                const message_array   = msg.toJSON().data;
                const pubKey_array    = pk.toJSON().data;
                let verifyArgs = [signatureType, signature_array, argSigLen, message_array, mlen, pubKey_array, pklen];
                let ret = await falconInstance.callStatic.verify.apply(null, verifyArgs);
                let errorReasonCode = getReasonCode(ret);
                ret = getFalconReturnValue(ret);
                let errorStr = "ERROR: falcon.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
                if (ret != expectedRet) console.log(errorStr);
                assert.equal(ret, expectedRet, errorStr);
                let tx = await falconInstance.verify.apply(null, verifyArgs);
                let receipt = await tx.wait();
                assert.equal(receipt.status, true);
            }
          }));
        });


      });

      it.skip("dummy", () =>
      {
        // Mocha needs at least one explicit declaration otherwise it ignores the whole suite.
      });


      const parseKats = async (katStream) =>
      {
        const rl = readline.createInterface( {input: katStream, crlfDelay: Infinity} );
        let kats = [];
        let kat = {};
        for await (const line of rl)
        {
          if (line.startsWith("#"))
          {
            continue;
          }
          if (line.length === 0)
          {
            if (Object.keys(kat).length !== 0)
            {
              kats.push(kat);
            }
            kat = {};
            continue;
          }
          const katLine = line.split('=');
          kat[katLine[0].trim()] = katLine[1].trim();
        }
        return kats;
      }

      const getFalconReturnValue = (ret) =>
      {
        var isNegative = false;
        if (ret < 0)
        {
          isNegative = true;
          ret = Math.abs(ret);
        }
        var remainder = ret % 10;
        if (isNegative)
          remainder = -remainder;
        return remainder;
      }

      const getReasonCode = (ret) =>
      {
        var isNegative = false;
        if (ret < 0)
        {
          isNegative = true;
          ret = Math.abs(ret);
        }
        var remainder = ret % 10;
        var quotient = ret - remainder; // or maybe Math.floor(ret/10) or trunc(ret/10)
        if (isNegative)
          quotient = -quotient;
        return quotient;
      }
    });
});


/*
// Extracts from NIST spec for easy reference:
//
// 3.11.3 Signatures
// A Falcon signature consists of two strings r and s. They may conceptually be
// encoded separately, because the salt r must be known before beginning to hash
// the message itself, while the s value can be obtained or verified only after
// the whole message has been processed. In a format that supports streamed
// processing of long messages, the salt r would normally be encoded before the
// message, while the s value would appear after the message bytes. However, we
// here define an encoding that includes both r and s.
//
// The first byte is a header with the following format (bits indicated from most to least significant):
//     0 c c 1 n n n n
// with these conventions:
//     • The leftmost bit is 0, and the fourth bit from the left is 1 (in
//       previous versions of Falcon, these bits may had have different values).
//     • Bits cc are 01 or 10 to specify the encoding method for s. Encoding 01
//       uses the compression algorithm described in Section 3.11.2; encoding 10
//       is alternate uncompressed encoding in which each coefficient of s is
//       encoded over a fixed number of bits.
//     • Bits nnnn encode a value ℓ such that the Falcon degree is n = 2ℓ
//         . ℓ must be in the allowed range (1 to 10).
// Following the header byte are the nonce string r (40 bytes), then the encoding of s itself.
//
// Signatures are then normally padded with zeros up to the prescribed length
// (sbytelen). Verifiers may also support unpadded signatures, which do not have
// a fixed size, but are (on average) slightly shorter than padded signatures.
// Partial padding is not valid: if the signature has padding bytes, then all
// padding bytes must be zero, and the total padded length must be equal to
// sbytelen.
//
// When using the alternate uncompressed format (cc is 10 in the header byte),
// all elements of sare encoded over exactly 12 bits each (signed big-endian
// encoding, using two’s complement for negative integers; the valid range is
// −2047 to +2047, the value −2048 being forbidden)2.
// This uncompressed format yields larger signatures and is meant to support the
// uncommon situations in which signature values and signed messages are secret:
// uncompressed signatures can be decoded and encoded with constant-time
// implementations that do not leak information through timing-based side
// channels.
*/


/*
// 3.11.6 NIST API
// The API to be implemented by candidates to the NIST call for post-quantum algorithms mandates a
// different convention, in which the signed message and the signature are packed into a single aggregate
// format. In this API, the following encoding is used:
//     • First two bytes are the “signature length” (big-endian encoding).
//     • Then follows the nonce r (40 bytes).
//     • The message data itself appears immediately after the nonce.
//     • The signature comes last. This signature uses a nonce-less format:
//         – Header byte is: 0010nnnn
//         – Encoded s immediately follows, using compressed encoding.
// There is no signature padding; the signature has a variable length. The length specified in the first two
// bytes of the package is the length, in bytes, of the signature, including its header byte, but not including
// the nonce length.
*/
