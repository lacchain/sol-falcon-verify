#!/usr/bin/env node
'use strict';

var assert = require('assert');

const falcConsts = require('./falcon_constants.js');
const kestrelDataset = require('./falcon_dataset_from_kestrel.js');

const falconContract = artifacts.require("Falcon");


function getFalconReturnValue(ret)
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


function getReasonCode(ret)
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


function numHex(s)
{
    var a = s.toString(16).toUpperCase();
    if ((a.length % 2) > 0)
    {
        a = "0" + a;
    }
    return a;
}


function strHex(s)
{
    var a = "";
    for (var i=0; i<s.length; i++)
    {
        a = a + numHex(s.charCodeAt(i));
    }

    return a;
}


contract("Falcon", accounts =>
{
    let falconInstance;

    before(async () =>
    {
        falconInstance = await falconContract.deployed();
    });

    //it("has EIP-152 enabled", async () =>
    //{
    //    // from https://eips.ethereum.org/EIPS/eip-152#test-vector-4
    //    let ret = await web3.eth.call(
    //    {
    //        from: accounts[0],
    //        to: '0x0000000000000000000000000000000000000009',
    //        data: '0x0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001'
    //    });
    //    assert.equal(ret, '0x08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b')
    //});

    describe("Interaction", async () =>
    {
        it("must be possible using hardcoded arrays", async () =>
        {
            //let signatureType = falcConsts.FALCON_SIG_0_INFERRED;
            //let signatureLen = 3;
            //let signature = [1,2,3];
            //let messageLen = 3;
            //let message = [1,2,3];
            //let pubKeyLen = 3;
            //let pubKey = [1,2,3];
            let expectedRet = falcConsts.FALCON_ERR_SIZE;

            //let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let verifyArgs = [0, [1,2,3], 3, [1,2,3], 3, [1,2,3], 3];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });

        it("must be possible using malloc'd arrays", async () =>
        {
            let signatureType = falcConsts.FALCON_SIG_0_INFERRED;
            let signatureLen = 42;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 0;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_FORMAT;

            //signature.write('11', 0, 1, 'hex');  // First byte should have the form "0cc1nnnn"
            //pubKey.write('01', 0, 1, 'hex'); // If logn=1, then pubkey size is expected to be 5 bytes (see FALCON_PUBKEY_SIZE). For Falcon512, logn=9 yielding pubkeysize of 897 bytes.

            const signature_array = signature.toJSON().data;  // new Uint8Array(signature);
            const message_array   = message.toJSON().data;    // new Uint8Array(message);
            const pubKey_array    = pubKey.toJSON().data;     // new Uint8Array(pubKey);

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });
    });
    
    describe("Public Key", async () =>
    {
        it("must have length of more than zero", async () =>
        {
            let signatureType = falcConsts.FALCON_SIG_0_INFERRED;
            let signatureLen = 42;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 0;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_SIZE;

            // logn: nnnn = log of degree, 9 for Falcon-512, 10 for Falcon-1024
            signature.write('19', 0, 1, 'hex');  // First byte should have the form "0cc1nnnn"
            //pubKey.write('09', 0, 1, 'hex'); // If logn=1, then pubkey size is expected to be 5 bytes (see FALCON_PUBKEY_SIZE). For Falcon512, logn=9 yielding pubkeysize of 897 bytes.

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });

        it("must have a 1st nibble value of 0", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_0_INFERRED;
            let signatureLen = 42;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 5;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_FORMAT;

            signature.write('11', 0, 1, 'hex');  // First byte should have the form "0cc1nnnn"
            pubKey.write('B1', 0, 1, 'hex'); // If logn=1, then pubkey size is expected to be 5 bytes (see FALCON_PUBKEY_SIZE). For Falcon512, logn=9 yielding pubkeysize of 897 bytes.

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });

        it("must have a 2nd nibble value in the range 1 to 10", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_0_INFERRED;
            let signatureLen = 42;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 1;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_FORMAT;

            signature.write('1B', 0, 1, 'hex');  // First byte should have the form "0cc1nnnn"
            pubKey.write('0B', 0, 1, 'hex'); // If logn=1, then pubkey size is expected to be 5 bytes (see FALCON_PUBKEY_SIZE). For Falcon512, logn=9 yielding pubkeysize of 897 bytes.

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });

        it("must have the correct length", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_1_COMPRESSED;
            let signatureLen = 44;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 4;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_SIZE;

            signature.write('31', 0, 1, 'hex');  // First byte should have the form "0cc1nnnn"
            pubKey.write('01', 0, 1, 'hex'); // If logn=1, then pubkey size is expected to be 5 bytes (see FALCON_PUBKEY_SIZE). For Falcon512, logn=9 yielding pubkeysize of 897 bytes.

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });
    });

    describe("Signature", async() =>
    {
    	
    	it("must have a SignatureType in the range 0..3", async () =>
        {
            let signatureType = falcConsts.FALCON_SIG_4_INVALID;
            let signatureLen = 44;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 1;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_BADARG;

            signature.write('71', 0, 1, 'hex');  // First byte should have the form "0cc1nnnn"
            pubKey.write('01', 0, 1, 'hex'); // If logn=1, then pubkey size is expected to be 5 bytes (see FALCON_PUBKEY_SIZE). For Falcon512, logn=9 yielding pubkeysize of 897 bytes.

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });

        it("must have a minimum length of 42 bytes", async () =>
        {
            let signatureType = falcConsts.FALCON_SIG_0_INFERRED;
            let signatureLen = 41;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 1;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_SIZE;

            signature.write('11', 0, 1, 'hex');  // First byte should have the form "0cc1nnnn"
            pubKey.write('01', 0, 1, 'hex'); // If logn=1, then pubkey size is expected to be 5 bytes (see FALCON_PUBKEY_SIZE). For Falcon512, logn=9 yielding pubkeysize of 897 bytes.

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });

        it("must have the same 2nd nibble as that of the public key", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_0_INFERRED;
            let signatureLen = 42;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 5;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_BADARG;

            signature.write('12', 0, 1, 'hex');  // First byte should have the form "0cc1nnnn"
            pubKey.write('01', 0, 1, 'hex'); // If logn=1, then pubkey size is expected to be 5 bytes (see FALCON_PUBKEY_SIZE). For Falcon512, logn=9 yielding pubkeysize of 897 bytes.

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });
    });

    describe("Signature Type (0cc1nnnn)", async() =>
    {
        // NB This test cannot fail: by definition, two consecutive bits will always represent a value of 0, 1, 2 or 3
        // i.e. falcConsts.FALCON_SIG_0_INFERRED (0), falcConsts.FALCON_SIG_1_COMPRESSED (1), falcConsts.FALCON_SIG_2_PADDED (2), falcConsts.FALCON_SIG_3_CT (3)
        // Valid values of 0cc1 are : 0001, 0011, 0101, 0111 = 1, 3, 5, 7
        it("must have a value (cc) of 0, 1, 2 or 3", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_0_INFERRED;
            let signatureLen = 42;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 5;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_FORMAT;

            signature.write('41', 0, 1, 'hex');  // First byte should have the form "0cc1nnnn"
            pubKey.write('01', 0, 1, 'hex'); // If logn=1, then pubkey size is expected to be 5 bytes (see FALCON_PUBKEY_SIZE). For Falcon512, logn=9 yielding pubkeysize of 897 bytes.

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });
    });

    describe("Inferred Signature Type (0)", async() =>
    {
        it("must have the 1st nibble of the signature equal to 1 (0001)", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_0_INFERRED;
            let signatureLen = 42;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 5;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_FORMAT;

            signature.write('21', 0, 1, 'hex'); // Happy first nibble is b0001, so we'll put b0000 to force BADSIG
            pubKey.write('01', 0, 1, 'hex'); // If logn=1, then pubkey size is expected to be 5 bytes (see FALCON_PUBKEY_SIZE). For Falcon512, logn=9 yielding pubkeysize of 897 bytes.

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });

        it("must have the correct signature length in the public key", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_0_INFERRED;
            let signatureLen = 42;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 1;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_SIZE;

            signature.write('11', 0, 1, 'hex'); // Set the value of the 1st byte
            pubKey.write('01', 0, 1, 'hex'); // 1 means signature size of 44 bytes

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });
    });

    describe("Compressed Signature Type (1)", async() =>
    {
        it("must have the 1st nibble of the signature equal to 3 (0011)", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_1_COMPRESSED;
            let signatureLen = 42;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 5;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_FORMAT;

            signature.write('51', 0, 1, 'hex');
            pubKey.write('01', 0, 1, 'hex'); // 1 means signature size of 44 bytes

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });
        // We cannot make any assumptions about the length of an unpadded compressed signature
    });

    describe("Padded Signature Type (2)", async() =>
    {
        it("must have the 1st nibble of the signature equal to 5 (0101)", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_2_PADDED;
            let signatureLen = 42;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 5;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_FORMAT;

            signature.write('31', 0, 1, 'hex');
            pubKey.write('01', 0, 1, 'hex'); // 1 means signature size of 44 bytes

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });

        it("must have the correct signature length in the public key", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_2_PADDED;
            let signatureLen = 42;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 1;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_SIZE;

            signature.write('51', 0, 1, 'hex'); // Set the value of the 1st byte
            pubKey.write('01', 0, 1, 'hex'); // 1 means signature size of 44 bytes

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });
    });

    describe("Constant-Time Signature Type (3)", async() =>
    {
        it("must have the 1st nibble of the signature equal to 7 (0111)", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_3_CT;
            let signatureLen = 44;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 5;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_FORMAT;

            signature.write('51', 0, 1, 'hex');
            pubKey.write('01', 0, 1, 'hex'); // 1 means signature size of 44 bytes

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });

        it("must have the correct signature length in the public key", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_3_CT;
            let signatureLen = 42;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 1;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 1;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_SIZE;

            signature.write('71', 0, 1, 'hex'); // Set the value of the 1st byte
            pubKey.write('01', 0, 1, 'hex'); // 1 means signature size of 44 bytes

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });
    });

    describe("Message", async() =>
    {
        it("must have a length of more than zero", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_1_COMPRESSED;
            let signatureLen = 44;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 0;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 1;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_SIZE;

            signature.write('31', 0, 1, 'hex');     // Set the value of the 1st byte
            pubKey.write('01', 0, 1, 'hex'); // 1 means signature size of 44 bytes

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });
    });

    describe("Signature Validation", async() =>
    {
        it("must fail with invalid data", async () =>
        {
            let signatureType = falcConsts.FALCON_SIG_0_INFERRED;
            let signatureLen = 658;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 100;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 897;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_BADSIG;

            if (1)
            {
                signature.write(
                '1955555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '555555555555555555555555555555555555', 0, signatureLen, 'hex');
                pubKey.write(
                '0955555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '55', 0, pubKeyLen, 'hex');
                message.write(
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '5555555555555555555555555555555555555555555555555555555555555555' +
                '55555555', 0, messageLen, 'hex');
            }

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet) console.log(errorStr);
            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });

        ///////////////////////////////////////////////////////////
        // Ultimate Goal
        ///////////////////////////////////////////////////////////
        it("should succeed if all fields are valid", async() =>
        {
            let signatureType = falcConsts.FALCON_SIG_1_COMPRESSED;
            let signatureLen = 658; // kestrelDataset.signatureLen;
            let signature = Buffer.alloc(signatureLen);
            let messageLen = 100;   // kestrelDataset.messageLen;
            let message = Buffer.alloc(messageLen);
            let pubKeyLen = 897;    // kestrelDataset.pubKeyLen;
            let pubKey = Buffer.alloc(pubKeyLen);
            let expectedRet = falcConsts.FALCON_ERR_SUCCESS;

            //console.log("signatureLen=" + signatureLen);
            //console.log("messageLen=" + messageLen);
            //console.log("pubKeyLen=" + pubKeyLen);

            if (0)
            {
                signature.write(kestrelDataset.signatureInHex, 0, signatureLen, 'hex');
                message.write  (kestrelDataset.messageInHex  , 0, messageLen  , 'hex');
                pubKey.write(kestrelDataset.pubKeyInHex, 0, pubKeyLen   , 'hex');
            }
            if (1)
            {
                signature.write(
                '390191EF48486EB9D9A6823D8E6FF0D7F4DF8BED13AF7FA55A7E8DFA0D197258' +
                '42A5451BCF4C061982D021C63A7D666C2024FE57033B1A1BDA8C2179C518C94D' +
                '434947EACC109EFE792857FF6450CC853E8BB9D5D951B3DDB1397FADC2210762' +
                'B479E386E660A68EB2AD034A58A3D0CCE2370EDF257FF4F81FE97C9BB10C1A96' +
                'EE87D2414FDF4EA39F9F7C0604D1A3AEBE5D73A6A1F7221A99EB2389B905DA94' +
                '766CD27A9A89F13D56B97CDD346689CFC5B3BDBBDC5102D3B5F93A2A95BE40AF' +
                'CAAC416D831391474C2298DA0A359BC958A5F227DE991A338944D6EBE4963F1A' +
                '4BA5BB3D5C672526992329C84C5770C03A5E43504A28FA86F3B9BD72354C0B19' +
                '21D1B568E5212856D8436F79A8C409E631082A4E28B7CB99D89C2A9AB3C196C5' +
                '6A77E6D05718196B316D8E9BEDCFC214E2A33C02F0AFD821DBFCB966C8BB8DDE' +
                '01C812A2045B6BC8DE767F97B739DC8ED262F43DFC092E49F34C7728839895E4' +
                '620620E4A193E94DBF2A9D439E249E6EC3377ED6734030ACD43D138B982C36DF' +
                '814A4257F971A53AA5D92A7670915469013E68124EDAE3FC11B4CA470938EE2F' +
                '218BC0E11468A6092F233DE914790C972F77D95F968AC5F6E0968E0EFA8D6288' +
                '25F3FBAD2254E04E9BA34DEFC698B2E19E9629290F4E5682270595035B07404B' +
                '091F5325293ED4021C619D7F0914AC47219B9E5DF6FDA5ACBB398ADB5C8540DC' +
                '3390A548D82BE42FAC8F6EF9963546BCF278E63FDD49D0ABBE62208E39564687' +
                '71DF4A50DD7A3AA197D81F58C14425EE166D29AEF3EB2C171FF9B24F575E0AE9' +
                'A65227D1E57AB6C5DF11A369645DAC717AB671A4C10AEF72824134D0E68676BB' +
                '138CA20EB5E08A0D1F90EE48AF1CCE1F21C72394AC427F382CED545183689CDB' +
                '72CEC8EA30C77389A16204356259E4B1142D', 0, signatureLen, 'hex');
                message.write(
                '486C8E99DE7F81A3B0F4610BB555BE687D67E079F5B03EE9D18C21D766FE3D2D' +
                '36EA378A89294F839DC9BCD9A8251F92CFD39AACC1E228F44442E95B3C59EF90' +
                '4613ECE9D312028B07A3CB26B3C9844DCDB2699299D7D47FD63F7889D6C5CE34' +
                '626B583A', 0, messageLen  , 'hex');
                pubKey.write(
                '09B7107F987F937EA7566BCA38E1578B8D0B59294E68BD208BFA90133101F5EF' +
                'D8755E9F1FD20564762585BAA5A4F165EBEC6DF80AB5248A22BBA940A7754ABE' +
                '5329B5C60345F395AD2A33AC106E65F14B91D0DCA308AE4CC6DB5FE69EEE9FE4' +
                'A392FF64F52865070EB5587E7F83AB6C187CC0584B3552920A3D4B50AB0A4A1E' +
                '8D9DEA3D4B5EB015A2F4AB59AE3D0AD2C081D8D2428A83806DE7973EC65975FF' +
                '8FD7287C642B6A83250255B61838CB4D68C52600B8C5330FCE48AAEB806D4FB9' +
                '9A9ADD5E56577454A5A5AD5699711DD04854BF11484713DEA5D9ABD17F9214C3' +
                '3C4F4D47A6600BC241011F52E29D9820AC85AB70DFCCB1D08C003B489C0826BF' +
                '28CCEE71945637B7161E6A99584451BF8351A43A0B0755CE3044F0840B7AD048' +
                '9E6572C896666463E2CFC8EBE1258E3A963AB1433B173865705C15F044BCFDE1' +
                'B780D29E422604A9081D2349F6D6B40671B7C6AE77F44C16A22412E9E32CB116' +
                '363D99CA4D2C3ACE6730FD45FC6612D389EDCD1C9B2201BA32A4705FAC61005E' +
                '184B89A4C90983ACD7AFEE694AC9D904473EB512EC2D4875C1C954B791506F02' +
                'C9E65F5D04976EA4E81D22D4884EB1C47EEB1A7EE109E12E61CE0EE4DFA88FDA' +
                'CB78ED61B0A327C2069D8CD33D184E68A60C22F6804FACECA968CF5C1C276C7D' +
                '16386F38BB82D5EA1E11D801F5EF33D3A3B0171DC870741CE8373C779AE89352' +
                '11348C436285703681F1E6B0ADC05C35C56196C246731EE2A4A998EF918A1650' +
                '23A76D324C58419CD9E76EBCA0E13823D90B2EBC641717B404E2EE2937D48B38' +
                '441E88F1086C15C95DE8A48632BEE5FB56F99F07AC31037323000317C291E2EA' +
                'CE7865ECE23548E804679241F1366748B1656CD58C28B86D5E08E269D0E3A668' +
                'A834F4178A188DD63384042773FAC10B3D96F533ECABE3A8A27E091D5846D6EA' +
                'D8AC9241437240AD4F7D274B78403402210AD042DDF73D59E02ABF657AA41E10' +
                '1455DF638D44C181E4CA219F2C6679088FF11AF439115D8EF38F3614B957E1EB' +
                'B9CC2E6BEE0C0664DA7BA3F1268404A5BAC8ED45854881972382908861CC7F14' +
                'F5D03B112273917854617590AAD70EEEDF398CB206FF5C7F7A9C5390DFA27E14' +
                'B1148518833B3375CDFAF5A73680CDD7D0EA5F664672FE91AE6700032A3EE21A' +
                'EB3AB7B6A0F66B0F65597A7FB6F5C1A9B1459D48885DB3734ABEC9918C0F3A81' +
                '35BBB2279984A054115E9C12A8F10CA25B93BE8A3ACFB94DC6A90D4DA0E0A7AD' +
                'A8', 0, pubKeyLen   , 'hex');
            }

            //console.log("signature[0..8]=" + strHex(signature.toString('ascii',0,8)) );
            //console.log("signature[0..8]=" + strHex(signature.toString('ascii',0,1))
            //                               + strHex(signature.toString('ascii',1,2))
            //                               + strHex(signature.toString('ascii',2,3))
            //                               + strHex(signature.toString('ascii',3,4))
            //                               );
            //console.log("signature[0..8]=" + signature.toString('HEX',0,8).toUpperCase() );
            //console.log("message[0..8]  =" + message.toString('hex',0,8).toUpperCase() );
            //console.log("pubKey[0..8]   =" + pubKey.toString('hex',0,8).toUpperCase() );

            const signature_array = signature.toJSON().data;
            const message_array   = message.toJSON().data;
            const pubKey_array    = pubKey.toJSON().data;

            let verifyArgs = [signatureType, signature_array, signatureLen, message_array, messageLen, pubKey_array, pubKeyLen];
            let ret = await falconInstance.verify.call.apply(null, verifyArgs);
            let errorReasonCode = getReasonCode(ret);
            ret = getFalconReturnValue(ret);
            let errorStr = "ERROR: falconInstance.verify expected " + expectedRet + " (" + falcConsts.FALCON_ERR_Description[Math.abs(expectedRet)] + "), but got " + ret + " (" + falcConsts.FALCON_ERR_Description[Math.abs(ret)] + ") [reason: " + errorReasonCode + "]";
            if (ret != expectedRet)
            {
                console.log(errorStr);
            }

            assert.equal(ret, expectedRet, errorStr);
            let tx = await falconInstance.verify.sendTransaction.apply(null, verifyArgs);
            assert.equal(tx.receipt.status, true);
        });
    });

});
