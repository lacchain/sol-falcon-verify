// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

// Some parts: Apache-2.0

/* TODO: ==>
TODO: <== */

// ==== sha3_c.c BEGIN =====================================================================================================================

////////////////////////////////////////
// A) The following code was imported from "fips202.c"
// Based on the public domain implementation in
// crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html
// by Ronny Van Keer
// and the public domain "TweetFips202" implementation
// from https://twitter.com/tweetfips202
// by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe
// License: Public domain
//
// B) SHAKE256_RATE constant from...
// file: sha3_c.c
// brief: Implementation of the OQS SHA3 API via the files fips202.c
// from: PQClean (https://github.com/PQClean/PQClean/tree/master/common)
// License: MIT
////////////////////////////////////////

contract Falcon
{
    // ***************************************************************************
    // ** State variables in 'storage'
    // ***************************************************************************

    ///////////////////////////////////////
    // Constants
    ///////////////////////////////////////
    uint32 constant SHAKE256_RATE = 136;  // The SHAKE-256 byte absorption rate (aka OQS_SHA3_SHAKE256_RATE)
    int16  constant private CTX_ELEMENTS = 26; // Number of uint64 context elements
    int16  constant private PQC_SHAKEINCCTX_BYTES = (8 * CTX_ELEMENTS); // (sizeof(uint64) * 26)
    int16  constant private NROUNDS = 24;

    ///////////////////////////////////////
    // Variables
    ///////////////////////////////////////
    // Space to hold the state of the SHAKE-256 incremental hashing API.
    // uint64[26]: Input/Output incremental state
    //              * First 25 values represent Keccak state.
    //              * 26th value represents either the number of absorbed bytes
    //                that have not been permuted, or not-yet-squeezed bytes.
    //byte[PQC_SHAKEINCCTX_BYTES]  constant private  shake256_context; // Internal state.
    uint64[CTX_ELEMENTS] private shake256_context64; // Internal state.

    // Keccak round constants
    uint64[NROUNDS] private KeccakF_RoundConstants =
    [
    	0x0000000000000001, 0x0000000000008082,
    	0x800000000000808a, 0x8000000080008000,
    	0x000000000000808b, 0x0000000080000001,
    	0x8000000080008081, 0x8000000000008009,
    	0x000000000000008a, 0x0000000000000088,
    	0x0000000080008009, 0x000000008000000a,
    	0x000000008000808b, 0x800000000000008b,
    	0x8000000000008089, 0x8000000000008003,
    	0x8000000000008002, 0x8000000000000080,
    	0x000000000000800a, 0x800000008000000a,
    	0x8000000080008081, 0x8000000000008080,
    	0x0000000080000001, 0x8000000080008008
    ];



    // ***************************************************************************
    // ** Implementation: Utility functions
    // ***************************************************************************

    ////////////////////////////////////////
    // Solidity implementation of the macro...
    // #define ROL(a, offset) (((a) << (offset)) ^ ((a) >> (64 - (offset))))
    ////////////////////////////////////////
    function ROL(uint64 a, uint16 offset) private pure returns (uint64)
    {
        return (((a) << (offset)) ^ ((a) >> (64 - (offset))));
    }


    ///////////////////////////////////////
    //
    ///////////////////////////////////////
    function byte_array_uint16_get(bytes memory bytearray, uint32 wordindex) private pure returns (uint16 result16)
    {
        // If the array was an array of uint16 values:
        //     result16 = wordarray[wordindex];
        // TODO: Check me, incl endianess
        result16 = uint16((uint8(bytearray[wordindex*2]) << 8) | uint8(bytearray[wordindex*2+1]));
    }


    ///////////////////////////////////////
    //
    ///////////////////////////////////////
    function byte_array_uint16_set(bytes memory bytearray, uint32 wordindex, uint16 value16) private pure
    {
        // If the array was an array of uint16 values:
        //     wordarray[wordindex] = value16;
        // TODO: Check me, incl endianess
        bytearray[wordindex*2  ] = bytes1(uint8(uint16(value16) >> 8    ));
        bytearray[wordindex*2+1] = bytes1(uint8(uint16(value16) & 0x00FF));
    }


    ///////////////////////////////////////
    //
    ///////////////////////////////////////
    function byte_array_int16_set(bytes memory bytearray, uint32 wordindex, int16 value16) private pure
    {
        // If the array was an array of uint16 values:
        //     wordarray[wordindex] = value16;
        // TODO: Check me, incl endianess and sign
        bytearray[wordindex*2  ] = bytes1(uint8(int16(value16) >> 8    ));
        bytearray[wordindex*2+1] = bytes1(uint8(int16(value16) & 0x00FF));
    }


/*
    function toBytes(address a) public pure returns (bytes memory b)
    {
        // From Dave
        assembly
        {
            let m := mload(0x40)
            a := and(a, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            mstore(add(m, 20), xor(0x140000000000000000000000000000000000000000, a))
            mstore(0x40, add(m, 52))
            b := m
       }
    }

    function ArrayToBytes(uint8[40] memory a) public pure returns (bytes memory b)
    {
        ?????
        assembly
        {
            let m := mload(0x40)
            a := and(a, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
            mstore(add(m, 40), xor(0x140000000000000000000000000000000000000000, a))
            mstore(0x40, add(m, 52))
            b := m
       }
    }
*/

    // ***************************************************************************
    // ** Implementation: Keccak
    // ***************************************************************************

    ////////////////////////////////////////
    // State variables in 'storage'
    // Moved from local vars in KeccakF1600_StatePermute() to here in order to avoid stack overflow
    ////////////////////////////////////////
    uint64 Aba; uint64 Abe; uint64 Abi; uint64 Abo; uint64 Abu;
    uint64 Aga; uint64 Age; uint64 Agi; uint64 Ago; uint64 Agu;
    uint64 Aka; uint64 Ake; uint64 Aki; uint64 Ako; uint64 Aku;
    uint64 Ama; uint64 Ame; uint64 Ami; uint64 Amo; uint64 Amu;
    uint64 Asa; uint64 Ase; uint64 Asi; uint64 Aso; uint64 Asu;
    uint64 BCa; uint64 BCe; uint64 BCi; uint64 BCo; uint64 BCu;
    uint64 Da ; uint64 De ; uint64 Di ; uint64 Do ; uint64 Du ;
    uint64 Eba; uint64 Ebe; uint64 Ebi; uint64 Ebo; uint64 Ebu;
    uint64 Ega; uint64 Ege; uint64 Egi; uint64 Ego; uint64 Egu;
    uint64 Eka; uint64 Eke; uint64 Eki; uint64 Eko; uint64 Eku;
    uint64 Ema; uint64 Eme; uint64 Emi; uint64 Emo; uint64 Emu;
    uint64 Esa; uint64 Ese; uint64 Esi; uint64 Eso; uint64 Esu;

    ////////////////////////////////////////
    // KeccakF1600_StatePermute()
    // Input parameters supplied in member variable shake256_context64.
    // Output values are written to the same member variable.
    ////////////////////////////////////////
    function KeccakF1600_StatePermute() public payable
    {
        //fprintf(stdout, "TRACE: KeccakF1600_StatePermute()\n");
        int         round;

        // copyFromState(A, state)
        Aba = shake256_context64[ 0]; Abe = shake256_context64[ 1]; Abi = shake256_context64[ 2]; Abo = shake256_context64[ 3]; Abu = shake256_context64[ 4];
        Aga = shake256_context64[ 5]; Age = shake256_context64[ 6]; Agi = shake256_context64[ 7]; Ago = shake256_context64[ 8]; Agu = shake256_context64[ 9];
        Aka = shake256_context64[10]; Ake = shake256_context64[11]; Aki = shake256_context64[12]; Ako = shake256_context64[13]; Aku = shake256_context64[14];
        Ama = shake256_context64[15]; Ame = shake256_context64[16]; Ami = shake256_context64[17]; Amo = shake256_context64[18]; Amu = shake256_context64[19];
        Asa = shake256_context64[20]; Ase = shake256_context64[21]; Asi = shake256_context64[22]; Aso = shake256_context64[23]; Asu = shake256_context64[24];

        for (round = 0; round < NROUNDS; round += 2)
        {
            // PrepareTheta
            BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
            BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
            BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
            BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
            BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

            // thetaRhoPiChiIotaPrepareTheta(round  , A, E)
            Da = BCu ^ ROL(BCe, 1);
            De = BCa ^ ROL(BCi, 1);
            Di = BCe ^ ROL(BCo, 1);
            Do = BCi ^ ROL(BCu, 1);
            Du = BCo ^ ROL(BCa, 1);
            Aba ^= Da;
            BCa = Aba;
            Age ^= De;
            BCe = ROL(Age, 44);
            Aki ^= Di;
            BCi = ROL(Aki, 43);
            Amo ^= Do;
            BCo = ROL(Amo, 21);
            Asu ^= Du;
            BCu = ROL(Asu, 14);
            Eba = BCa ^ ((~BCe) & BCi);
            Eba ^= KeccakF_RoundConstants[uint256(round)];
            Ebe = BCe ^ ((~BCi) & BCo);
            Ebi = BCi ^ ((~BCo) & BCu);
            Ebo = BCo ^ ((~BCu) & BCa);
            Ebu = BCu ^ ((~BCa) & BCe);
            Abo ^= Do;
            BCa = ROL(Abo, 28);
            Agu ^= Du;
            BCe = ROL(Agu, 20);
            Aka ^= Da;
            BCi = ROL(Aka, 3);
            Ame ^= De;
            BCo = ROL(Ame, 45);
            Asi ^= Di;
            BCu = ROL(Asi, 61);
            Ega = BCa ^ ((~BCe) & BCi);
            Ege = BCe ^ ((~BCi) & BCo);
            Egi = BCi ^ ((~BCo) & BCu);
            Ego = BCo ^ ((~BCu) & BCa);
            Egu = BCu ^ ((~BCa) & BCe);
            Abe ^= De;
            BCa = ROL(Abe, 1);
            Agi ^= Di;
            BCe = ROL(Agi, 6);
            Ako ^= Do;
            BCi = ROL(Ako, 25);
            Amu ^= Du;
            BCo = ROL(Amu, 8);
            Asa ^= Da;
            BCu = ROL(Asa, 18);
            Eka = BCa ^ ((~BCe) & BCi);
            Eke = BCe ^ ((~BCi) & BCo);
            Eki = BCi ^ ((~BCo) & BCu);
            Eko = BCo ^ ((~BCu) & BCa);
            Eku = BCu ^ ((~BCa) & BCe);
            Abu ^= Du;
            BCa = ROL(Abu, 27);
            Aga ^= Da;
            BCe = ROL(Aga, 36);
            Ake ^= De;
            BCi = ROL(Ake, 10);
            Ami ^= Di;
            BCo = ROL(Ami, 15);
            Aso ^= Do;
            BCu = ROL(Aso, 56);
            Ema = BCa ^ ((~BCe) & BCi);
            Eme = BCe ^ ((~BCi) & BCo);
            Emi = BCi ^ ((~BCo) & BCu);
            Emo = BCo ^ ((~BCu) & BCa);
            Emu = BCu ^ ((~BCa) & BCe);
            Abi ^= Di;
            BCa = ROL(Abi, 62);
            Ago ^= Do;
            BCe = ROL(Ago, 55);
            Aku ^= Du;
            BCi = ROL(Aku, 39);
            Ama ^= Da;
            BCo = ROL(Ama, 41);
            Ase ^= De;
            BCu = ROL(Ase, 2);
            Esa = BCa ^ ((~BCe) & BCi);
            Ese = BCe ^ ((~BCi) & BCo);
            Esi = BCi ^ ((~BCo) & BCu);
            Eso = BCo ^ ((~BCu) & BCa);
            Esu = BCu ^ ((~BCa) & BCe);

            //    prepareTheta
            BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
            BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
            BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
            BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
            BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

            // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
            Da = BCu ^ ROL(BCe, 1);
            De = BCa ^ ROL(BCi, 1);
            Di = BCe ^ ROL(BCo, 1);
            Do = BCi ^ ROL(BCu, 1);
            Du = BCo ^ ROL(BCa, 1);
            Eba ^= Da;
            BCa = Eba;
            Ege ^= De;
            BCe = ROL(Ege, 44);
            Eki ^= Di;
            BCi = ROL(Eki, 43);
            Emo ^= Do;
            BCo = ROL(Emo, 21);
            Esu ^= Du;
            BCu = ROL(Esu, 14);
            Aba = BCa ^ ((~BCe) & BCi);
            Aba ^= KeccakF_RoundConstants[uint256(round + 1)];
            Abe = BCe ^ ((~BCi) & BCo);
            Abi = BCi ^ ((~BCo) & BCu);
            Abo = BCo ^ ((~BCu) & BCa);
            Abu = BCu ^ ((~BCa) & BCe);
            Ebo ^= Do;
            BCa = ROL(Ebo, 28);
            Egu ^= Du;
            BCe = ROL(Egu, 20);
            Eka ^= Da;
            BCi = ROL(Eka, 3);
            Eme ^= De;
            BCo = ROL(Eme, 45);
            Esi ^= Di;
            BCu = ROL(Esi, 61);
            Aga = BCa ^ ((~BCe) & BCi);
            Age = BCe ^ ((~BCi) & BCo);
            Agi = BCi ^ ((~BCo) & BCu);
            Ago = BCo ^ ((~BCu) & BCa);
            Agu = BCu ^ ((~BCa) & BCe);
            Ebe ^= De;
            BCa = ROL(Ebe, 1);
            Egi ^= Di;
            BCe = ROL(Egi, 6);
            Eko ^= Do;
            BCi = ROL(Eko, 25);
            Emu ^= Du;
            BCo = ROL(Emu, 8);
            Esa ^= Da;
            BCu = ROL(Esa, 18);
            Aka = BCa ^ ((~BCe) & BCi);
            Ake = BCe ^ ((~BCi) & BCo);
            Aki = BCi ^ ((~BCo) & BCu);
            Ako = BCo ^ ((~BCu) & BCa);
            Aku = BCu ^ ((~BCa) & BCe);
            Ebu ^= Du;
            BCa = ROL(Ebu, 27);
            Ega ^= Da;
            BCe = ROL(Ega, 36);
            Eke ^= De;
            BCi = ROL(Eke, 10);
            Emi ^= Di;
            BCo = ROL(Emi, 15);
            Eso ^= Do;
            BCu = ROL(Eso, 56);
            Ama = BCa ^ ((~BCe) & BCi);
            Ame = BCe ^ ((~BCi) & BCo);
            Ami = BCi ^ ((~BCo) & BCu);
            Amo = BCo ^ ((~BCu) & BCa);
            Amu = BCu ^ ((~BCa) & BCe);
            Ebi ^= Di;
            BCa = ROL(Ebi, 62);
            Ego ^= Do;
            BCe = ROL(Ego, 55);
            Eku ^= Du;
            BCi = ROL(Eku, 39);
            Ema ^= Da;
            BCo = ROL(Ema, 41);
            Ese ^= De;
            BCu = ROL(Ese, 2);
            Asa = BCa ^ ((~BCe) & BCi);
            Ase = BCe ^ ((~BCi) & BCo);
            Asi = BCi ^ ((~BCo) & BCu);
            Aso = BCo ^ ((~BCu) & BCa);
            Asu = BCu ^ ((~BCa) & BCe);
        }

        // copyToState(state, A)
        shake256_context64[ 0] = Aba; shake256_context64[ 1] = Abe; shake256_context64[ 2] = Abi; shake256_context64[ 3] = Abo; shake256_context64[ 4] = Abu;
        shake256_context64[ 5] = Aga; shake256_context64[ 6] = Age; shake256_context64[ 7] = Agi; shake256_context64[ 8] = Ago; shake256_context64[ 9] = Agu;
        shake256_context64[10] = Aka; shake256_context64[11] = Ake; shake256_context64[12] = Aki; shake256_context64[13] = Ako; shake256_context64[14] = Aku;
        shake256_context64[15] = Ama; shake256_context64[16] = Ame; shake256_context64[17] = Ami; shake256_context64[18] = Amo; shake256_context64[19] = Amu;
        shake256_context64[20] = Asa; shake256_context64[21] = Ase; shake256_context64[22] = Asi; shake256_context64[23] = Aso; shake256_context64[24] = Asu;
    }

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function keccak_inc_init() public payable
    {
        uint32  i;

        //fprintf(stdout, "TRACE: keccak_inc_init()\n");
        for (i = 0; i < 25; ++i)
        {
            shake256_context64[i] = 0;
        }
        shake256_context64[25] = 0;
    }

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function keccak_inc_absorb(uint32 r, bytes memory m, uint32 mlen) public payable
    {
        uint32  i;

        //fprintf(stdout, "TRACE: keccak_inc_absorb()\n");
        while (mlen + shake256_context64[25] >= r)
        {
            for (i = 0; i < r - uint32(shake256_context64[25]); i++)
            {
                ///////////////////////////////////////////////////////////////////////////
                //uint64 x = shake256_context64[(shake256_context64[25] + i) >> 3];
                //uint64 y5 = shake256_context64[25] + i;
                //uint64 y6 = y5 & 0x07;
                //uint64 y7 = 8 * y6;
                //uint8  y8 = uint8(m[i]);
                //uint64 y9 = uint64(y8);
                //uint64 y = y9 << y7;
                //
                //x ^= y;
                ///////////////////////////////////////////////////////////////////////////

                shake256_context64[(shake256_context64[25] + i) >> 3] ^= (uint64(uint8(m[i])) << (8 * ((shake256_context64[25] + i) & 0x07)));
            }
            mlen -= uint32(r - shake256_context64[25]);
/* TODO: ==>
            m += (r - shake256_context64[25]);
TODO: <== */
            shake256_context64[25] = 0;

            // Input parameters supplied in member variable shake256_context64.
            // Output values are written to the same member variable.
            KeccakF1600_StatePermute();
        }

        for (i = 0; i < mlen; i++)
        {
            shake256_context64[(shake256_context64[25] + i) >> 3] ^= (uint64(uint8(m[i])) << (8 * ((shake256_context64[25] + i) & 0x07)));
        }
        shake256_context64[25] += mlen;

    }

    /*************************************************
     * Name:        keccak_inc_finalize
     *
     * Description: Finalizes Keccak absorb phase, prepares for squeezing
     *
     * Arguments:   - uint32 r     : rate in bytes (e.g., 168 for SHAKE128)
     *              - uint8 p      : domain-separation byte for different Keccak-derived functions
     **************************************************/
    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function keccak_inc_finalize(uint32 r, uint8 p) public payable
    {
        //fprintf(stdout, "TRACE: keccak_inc_finalize()\n");
        shake256_context64[shake256_context64[25] >> 3] ^= uint64(p) << (8 * (shake256_context64[25] & 0x07));
        shake256_context64[(r - 1) >> 3] ^= (uint64(128) << (8 * ((r - 1) & 0x07)));
        shake256_context64[25] = 0;
    }

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function keccak_inc_squeeze(/*uint8* h, */ uint32 outlen, uint32 r) private pure returns (bytes memory h)
    {
        //fprintf(stdout, "TRACE: keccak_inc_squeeze()\n");
/* TODO: ==>
        uint32  i;

        for (i = 0; i < outlen && i < shake256_context64[25]; i++)
        {
            h[i] = uint8(shake256_context64[(r - shake256_context64[25] + i) >> 3] >> (8 * ((r - shake256_context64[25] + i) & 0x07)));
        }

        h += i;
        outlen -= i;
        shake256_context64[25] -= i;

        while (outlen > 0)
        {
            // Input parameters supplied in member variable shake256_context64.
            // Output values are written to the same member variable.
            KeccakF1600_StatePermute(shake256_context64);
            for (i = 0; i < outlen && i < r; i++)
            {
                h[i] = uint8(shake256_context64[i >> 3] >> (8 * (i & 0x07)));
            }

            h += i;
            outlen -= i;
            shake256_context64[25] = r - i;
        }

        r = r;
        for (i = 0; i < outlen; i++)
        {
            h[i] = 0xAA;
        }
TODO: <== */
    }

    ///////////////////////////////////////
    // Implementation: OQS_SHA3_shake256_inc
    ///////////////////////////////////////

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function OQS_SHA3_shake256_inc_init() public payable
    {
        int16 ii;
        //fprintf(stdout, "TRACE: OQS_SHA3_shake256_inc_init()\n");
        for (ii=0; ii < CTX_ELEMENTS; ii++)
            shake256_context64[uint256(ii)] = 0;
        keccak_inc_init();
    }

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function OQS_SHA3_shake256_inc_absorb(bytes memory input, uint32 inlen) public payable
    {
        //fprintf(stdout, "TRACE: OQS_SHA3_shake256_inc_absorb()\n");
        keccak_inc_absorb(SHAKE256_RATE, input, inlen);
    }

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function OQS_SHA3_shake256_inc_finalize() public payable
    {
        //fprintf(stdout, "TRACE: OQS_SHA3_shake256_inc_finalize()\n");
        keccak_inc_finalize(SHAKE256_RATE, 0x1F);
    }

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function OQS_SHA3_shake256_inc_squeeze(/*uint8* output,*/ uint32 outlen) public pure returns (bytes memory output)
    {
        //fprintf(stdout, "TRACE: OQS_SHA3_shake256_inc_squeeze()\n");
        output = keccak_inc_squeeze(outlen, SHAKE256_RATE);
    }

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function OQS_SHA3_shake256_inc_ctx_release() public payable
    {
        int16 ii;
        //fprintf(stdout, "TRACE: OQS_SHA3_shake256_inc_ctx_release()\n");
        // Blat over any sensitive data
        for (ii=0; ii < CTX_ELEMENTS; ii++)
            shake256_context64[uint256(ii)] = 0;
    }

//}
// ==== sha3_c.c END =====================================================================================================================
// ==== common.c BEGIN =====================================================================================================================

//contract lib_falcon_common
//{
    uint16[11] overtab = [ 0, /* unused */ 65, 67, 71, 77, 86, 100, 122, 154, 205, 287 ];

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(bytes memory /*uint16**/ x, uint32 logn, bytes memory /* uint8 * */ workingStorage) public view
    {
        uint32 n;
        uint32 n2;
        uint32 u;
        uint32 m;
        uint32 p;
        uint32 over;
        //bytes memory /* uint16* */ tt1;
        uint16[63] memory tt2;

        //fprintf(stdout, "INFO: PQCLEAN_FALCON512_CLEAN_hash_to_point_ct() ENTRY\n");

        n = uint32(1) << logn;
        n2 = n << 1;
        over = overtab[logn];
        m = n + over;
        // tt1 = (uint16 *)workingStorage;
        for (u = 0; u < m; u++)
        {
            uint8[2] memory buf;
            uint32    w;
            uint32    wr;

            OQS_SHA3_shake256_inc_squeeze(/*buf,*/ 2 /*sizeof(buf)*/);
            w = (uint32(buf[0]) << 8) | uint32(buf[1]);
            wr = w - (uint32(24578) & (((w - 24578) >> 31) - 1));
            wr = wr - (uint32(24578) & (((wr - 24578) >> 31) - 1));
            wr = wr - (uint32(12289) & (((wr - 12289) >> 31) - 1));
            wr |= ((w - 61445) >> 31) - 1;
            if (u < n)
            {
                byte_array_uint16_set(x,u,uint16(wr));  //x[u] = uint16(wr);
            }
            else if (u < n2)
            {
                byte_array_uint16_set(workingStorage, (u-n), uint16(wr));  //tt1[u - n] = uint16(wr);
            }
            else
            {
                tt2[u - n2] = uint16(wr);
            }
        }

        for (p = 1; p <= over; p <<= 1)
        {
            uint32 v;

            v = 0;
            for (u = 0; u < m; u++)
            {
/* TODO: ==>        
                uint16 *s;
                uint16 *d;
                uint32  j;
                uint32  sv;
                uint32  dv;
                uint32  mk;

                if (u < n)
                {
                    s = &x[u];
                }
                else if (u < n2)
                {
                    s = &tt1[u - n];
                }
                else
                {
                    s = &tt2[u - n2];
                }

                sv = *s;
                j = u - v;
                mk = (sv >> 15) - 1U;
                v -= mk;
                if (u < p)
                {
                    continue;
                }

                if ((u - p) < n)
                {
                    d = &x[u - p];
                }
                else if ((u - p) < n2)
                {
                    d = &tt1[(u - p) - n];
                }
                else
                {
                    d = &tt2[(u - p) - n2];
                }

                dv = *d;

                mk &= -(((j & p) + 0x01FF) >> 9);
                *s = uint16(sv ^ (mk & (sv ^ dv)));
                *d = uint16(dv ^ (mk & (sv ^ dv)));
TODO: <== */
            }
        }
        //fprintf(stdout, "INFO: PQCLEAN_FALCON512_CLEAN_hash_to_point_ct() EXIT\n");
    }

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function PQCLEAN_FALCON512_CLEAN_is_short(bytes memory /* const int16_t * */ s1, bytes memory /* const int16_t* */ s2, uint32 logn) public pure returns (int32)
    {
        uint32 n;
        uint32 u;
        uint32 s;
        uint32 ng;

        n = uint32(1) << logn;
        s = 0;
        ng = 0;
        for (u = 0; u < n; u++)
        {
            int32 z;

            z = byte_array_uint16_get(s1,u);  //z = s1[u];
            s += uint32(z * z);
            ng |= s;

            z = byte_array_uint16_get(s2,u);  //z = s2[u];
            s += uint32(z * z);
            ng |= s;
        }

        s |= -(ng >> 31);

        //return s < ((uint32(7085) * uint32(12289)) >> (10 - logn));
        uint32 val = ((uint32(7085) * uint32(12289)) >> (10 - logn));
        if (s < val)
           return 1;
        return 0;
    }
//}
// ==== common.c END =====================================================================================================================
// ==== codec.c BEGIN =====================================================================================================================

//library lib_falcon_codec
//{
    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function PQCLEAN_FALCON512_CLEAN_modq_decode(bytes memory /*uint16 **/ x, uint16 logn, bytes memory /*const void**/ In, uint32 max_In_len)  public pure returns (uint32)
    {
        uint32        n;
        uint32        In_len;
        uint32        u;
        //uint8 *       buf;
        uint32        buf_ndx;
        uint32        acc;
        uint32        acc_len;

        n = uint32(1) << logn;
        In_len = ((n * 14) + 7) >> 3;
        if (In_len > max_In_len)
        {
            return 0;
        }

        //buf = In;
        buf_ndx = 0;
        acc     = 0;
        acc_len = 0;
        u       = 0;

        while (u < n)
        {
            acc = (acc << 8) | uint32(uint8(In[buf_ndx++]));   // acc = (acc << 8) | (*buf++);
            acc_len += 8;
            if (acc_len >= 14)
            {
                uint32 w;

                acc_len -= 14;
                w = (acc >> acc_len) & 0x3FFF;
                if (w >= 12289)
                {
                    return 0;
                }
                byte_array_uint16_set(x,u,uint16(w)); //x[u++] = uint16(w);
                u++;
            }
        }

        if ((acc & ((uint32(1) << acc_len) - 1)) != 0)
        {
            return 0;
        }

        return In_len;
    }

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function PQCLEAN_FALCON512_CLEAN_comp_decode(bytes memory /*int16_t**/ x, uint32 logn, bytes memory /*const void**/ In, uint32 max_In_len) public pure returns (uint32)
    {
        //const uint8 *buf;
        uint32  buf_ndx;
        uint32  n;
        uint32  u;
        uint32  v;
        uint32  acc;
        uint    acc_len;

        n = uint32(1) << logn;
        //buf = In;
        buf_ndx = 0;
        acc = 0;
        acc_len = 0;
        v = 0;
        for (u = 0; u < n; u++)
        {
            uint b;
            uint s;
            uint m;

            if (v >= max_In_len)
            {
                return 0;
            }

            acc = (acc << 8) | uint32(uint8(In[buf_ndx++])); // acc = (acc << 8) | uint32(buf[v++]);
            b = acc >> acc_len;
            s = b & 128;
            m = b & 127;

            for (;;)
            {
                if (acc_len == 0)
                {
                    if (v >= max_In_len)
                    {
                        return 0;
                    }
                    acc = (acc << 8) | uint32(uint8(In[buf_ndx++])); // acc = (acc << 8) | uint32(buf[v++]);
                    acc_len = 8;
                }

                acc_len--;
                if (((acc >> acc_len) & 1) != 0)
                {
                    break;
                }

                m += 128;
                if (m > 2047)
                {
                    return 0;
                }
            }
            int16 val = int16((s!=0) ? -int(m) : int(m));
            byte_array_int16_set(x,u,val); // x[u] = int16(s ? -int(m) : int(m));
        }
        return v;
    }
//}
// ==== codec.c END =====================================================================================================================
// ==== vrfy_constants.h BEGIN =====================================================================================================================

// Useful reference:
//    https://medium.com/@jeancvllr/solidity-tutorial-all-about-bytes-9d88fdb22676
//    https://medium.com/@jeancvllr/solidity-tutorial-all-about-libraries-762e5a3692f9

//contract lib_falcon_vrfy_constants
//{
    ////////////////////////////////////////
    // Constants for NTT.
    //   n = 2^logn  (2 <= n <= 1024)
    //   phi = X^n + 1
    //   q = 12289
    //   q0i = -1/q mod 2^16
    //   R = 2^16 mod q
    //   R2 = 2^32 mod q
    ////////////////////////////////////////
    uint32 constant Q   = 12289;
    uint32 constant Q0I = 12287;
    uint32 constant R   = 4091;
    uint32 constant R2  = 10952;

    ////////////////////////////////////////
    // Table for NTT, binary case:
    //   GMb[x] = R*(g^rev(x)) mod q
    // where g = 7 (it is a 2048-th primitive root of 1 modulo q)
    // and rev() is the bit-reversal function over 10 bits.
    ////////////////////////////////////////
    uint16[1024] GMb =
    [
        4091,  7888, 11060, 11208,  6960,  4342,  6275,  9759,
        1591,  6399,  9477,  5266,   586,  5825,  7538,  9710,
        1134,  6407,  1711,   965,  7099,  7674,  3743,  6442,
        10414,  8100,  1885,  1688,  1364, 10329, 10164,  9180,
        12210,  6240,   997,   117,  4783,  4407,  1549,  7072,
        2829,  6458,  4431,  8877,  7144,  2564,  5664,  4042,
        12189,   432, 10751,  1237,  7610,  1534,  3983,  7863,
        2181,  6308,  8720,  6570,  4843,  1690,    14,  3872,
        5569,  9368, 12163,  2019,  7543,  2315,  4673,  7340,
        1553,  1156,  8401, 11389,  1020,  2967, 10772,  7045,
        3316, 11236,  5285, 11578, 10637, 10086,  9493,  6180,
        9277,  6130,  3323,   883, 10469,   489,  1502,  2851,
        11061,  9729,  2742, 12241,  4970, 10481, 10078,  1195,
        730,  1762,  3854,  2030,  5892, 10922,  9020,  5274,
        9179,  3604,  3782, 10206,  3180,  3467,  4668,  2446,
        7613,  9386,   834,  7703,  6836,  3403,  5351, 12276,
        3580,  1739, 10820,  9787, 10209,  4070, 12250,  8525,
        10401,  2749,  7338, 10574,  6040,   943,  9330,  1477,
        6865,  9668,  3585,  6633, 12145,  4063,  3684,  7680,
        8188,  6902,  3533,  9807,  6090,   727, 10099,  7003,
        6945,  1949,  9731, 10559,  6057,   378,  7871,  8763,
        8901,  9229,  8846,  4551,  9589, 11664,  7630,  8821,
        5680,  4956,  6251,  8388, 10156,  8723,  2341,  3159,
        1467,  5460,  8553,  7783,  2649,  2320,  9036,  6188,
        737,  3698,  4699,  5753,  9046,  3687,    16,   914,
        5186, 10531,  4552,  1964,  3509,  8436,  7516,  5381,
        10733,  3281,  7037,  1060,  2895,  7156,  8887,  5357,
        6409,  8197,  2962,  6375,  5064,  6634,  5625,   278,
        932, 10229,  8927,  7642,   351,  9298,   237,  5858,
        7692,  3146, 12126,  7586,  2053, 11285,  3802,  5204,
        4602,  1748, 11300,   340,  3711,  4614,   300, 10993,
        5070, 10049, 11616, 12247,  7421, 10707,  5746,  5654,
        3835,  5553,  1224,  8476,  9237,  3845,   250, 11209,
        4225,  6326,  9680, 12254,  4136,  2778,   692,  8808,
        6410,  6718, 10105, 10418,  3759,  7356, 11361,  8433,
        6437,  3652,  6342,  8978,  5391,  2272,  6476,  7416,
        8418, 10824, 11986,  5733,   876,  7030,  2167,  2436,
        3442,  9217,  8206,  4858,  5964,  2746,  7178,  1434,
        7389,  8879, 10661, 11457,  4220,  1432, 10832,  4328,
        8557,  1867,  9454,  2416,  3816,  9076,   686,  5393,
        2523,  4339,  6115,   619,   937,  2834,  7775,  3279,
        2363,  7488,  6112,  5056,   824, 10204, 11690,  1113,
        2727,  9848,   896,  2028,  5075,  2654, 10464,  7884,
        12169,  5434,  3070,  6400,  9132, 11672, 12153,  4520,
        1273,  9739, 11468,  9937, 10039,  9720,  2262,  9399,
        11192,   315,  4511,  1158,  6061,  6751, 11865,   357,
        7367,  4550,   983,  8534,  8352, 10126,  7530,  9253,
        4367,  5221,  3999,  8777,  3161,  6990,  4130, 11652,
        3374, 11477,  1753,   292,  8681,  2806, 10378, 12188,
        5800, 11811,  3181,  1988,  1024,  9340,  2477, 10928,
        4582,  6750,  3619,  5503,  5233,  2463,  8470,  7650,
        7964,  6395,  1071,  1272,  3474, 11045,  3291, 11344,
        8502,  9478,  9837,  1253,  1857,  6233,  4720, 11561,
        6034,  9817,  3339,  1797,  2879,  6242,  5200,  2114,
        7962,  9353, 11363,  5475,  6084,  9601,  4108,  7323,
        10438,  9471,  1271,   408,  6911,  3079,   360,  8276,
        11535,  9156,  9049, 11539,   850,  8617,   784,  7919,
        8334, 12170,  1846, 10213, 12184,  7827, 11903,  5600,
        9779,  1012,   721,  2784,  6676,  6552,  5348,  4424,
        6816,  8405,  9959,  5150,  2356,  5552,  5267,  1333,
        8801,  9661,  7308,  5788,  4910,   909, 11613,  4395,
        8238,  6686,  4302,  3044,  2285, 12249,  1963,  9216,
        4296, 11918,   695,  4371,  9793,  4884,  2411, 10230,
        2650,   841,  3890, 10231,  7248,  8505, 11196,  6688,
        4059,  6060,  3686,  4722, 11853,  5816,  7058,  6868,
        11137,  7926,  4894, 12284,  4102,  3908,  3610,  6525,
        7938,  7982, 11977,  6755,   537,  4562,  1623,  8227,
        11453,  7544,   906, 11816,  9548, 10858,  9703,  2815,
        11736,  6813,  6979,   819,  8903,  6271, 10843,   348,
        7514,  8339,  6439,   694,   852,  5659,  2781,  3716,
        11589,  3024,  1523,  8659,  4114, 10738,  3303,  5885,
        2978,  7289, 11884,  9123,  9323, 11830,    98,  2526,
        2116,  4131, 11407,  1844,  3645,  3916,  8133,  2224,
        10871,  8092,  9651,  5989,  7140,  8480,  1670,   159,
        10923,  4918,   128,  7312,   725,  9157,  5006,  6393,
        3494,  6043, 10972,  6181, 11838,  3423, 10514,  7668,
        3693,  6658,  6905, 11953, 10212, 11922,  9101,  8365,
        5110,    45,  2400,  1921,  4377,  2720,  1695,    51,
        2808,   650,  1896,  9997,  9971, 11980,  8098,  4833,
        4135,  4257,  5838,  4765, 10985, 11532,   590, 12198,
        482, 12173,  2006,  7064, 10018,  3912, 12016, 10519,
        11362,  6954,  2210,   284,  5413,  6601,  3865, 10339,
        11188,  6231,   517,  9564, 11281,  3863,  1210,  4604,
        8160, 11447,   153,  7204,  5763,  5089,  9248, 12154,
        11748,  1354,  6672,   179,  5532,  2646,  5941, 12185,
        862,  3158,   477,  7279,  5678,  7914,  4254,   302,
        2893, 10114,  6890,  9560,  9647, 11905,  4098,  9824,
        10269,  1353, 10715,  5325,  6254,  3951,  1807,  6449,
        5159,  1308,  8315,  3404,  1877,  1231,   112,  6398,
        11724, 12272,  7286,  1459, 12274,  9896,  3456,   800,
        1397, 10678,   103,  7420,  7976,   936,   764,   632,
        7996,  8223,  8445,  7758, 10870,  9571,  2508,  1946,
        6524, 10158,  1044,  4338,  2457,  3641,  1659,  4139,
        4688,  9733, 11148,  3946,  2082,  5261,  2036, 11850,
        7636, 12236,  5366,  2380,  1399,  7720,  2100,  3217,
        10912,  8898,  7578, 11995,  2791,  1215,  3355,  2711,
        2267,  2004,  8568, 10176,  3214,  2337,  1750,  4729,
        4997,  7415,  6315, 12044,  4374,  7157,  4844,   211,
        8003, 10159,  9290, 11481,  1735,  2336,  5793,  9875,
        8192,   986,  7527,  1401,   870,  3615,  8465,  2756,
        9770,  2034, 10168,  3264,  6132,    54,  2880,  4763,
        11805,  3074,  8286,  9428,  4881,  6933,  1090, 10038,
        2567,   708,   893,  6465,  4962, 10024,  2090,  5718,
        10743,   780,  4733,  4623,  2134,  2087,  4802,   884,
        5372,  5795,  5938,  4333,  6559,  7549,  5269, 10664,
        4252,  3260,  5917, 10814,  5768,  9983,  8096,  7791,
        6800,  7491,  6272,  1907, 10947,  6289, 11803,  6032,
        11449,  1171,  9201,  7933,  2479,  7970, 11337,  7062,
        8911,  6728,  6542,  8114,  8828,  6595,  3545,  4348,
        4610,  2205,  6999,  8106,  5560, 10390,  9321,  2499,
        2413,  7272,  6881, 10582,  9308,  9437,  3554,  3326,
        5991, 11969,  3415, 12283,  9838, 12063,  4332,  7830,
        11329,  6605, 12271,  2044, 11611,  7353, 11201, 11582,
        3733,  8943,  9978,  1627,  7168,  3935,  5050,  2762,
        7496, 10383,   755,  1654, 12053,  4952, 10134,  4394,
        6592,  7898,  7497,  8904, 12029,  3581, 10748,  5674,
        10358,  4901,  7414,  8771,   710,  6764,  8462,  7193,
        5371,  7274, 11084,   290,  7864,  6827, 11822,  2509,
        6578,  4026,  5807,  1458,  5721,  5762,  4178,  2105,
        11621,  4852,  8897,  2856, 11510,  9264,  2520,  8776,
        7011,  2647,  1898,  7039,  5950, 11163,  5488,  6277,
        9182, 11456,   633, 10046, 11554,  5633,  9587,  2333,
        7008,  7084,  5047,  7199,  9865,  8997,   569,  6390,
        10845,  9679,  8268, 11472,  4203,  1997,     2,  9331,
        162,  6182,  2000,  3649,  9792,  6363,  7557,  6187,
        8510,  9935,  5536,  9019,  3706, 12009,  1452,  3067,
        5494,  9692,  4865,  6019,  7106,  9610,  4588, 10165,
        6261,  5887,  2652, 10172,  1580, 10379,  4638,  9949
    ];

    ////////////////////////////////////////
    // Table for inverse NTT, binary case:
    //   iGMb[x] = R*((1/g)^rev(x)) mod q
    // Since g = 7, 1/g = 8778 mod 12289.
    ////////////////////////////////////////
    uint16[1024] iGMb =
    [
        4091,  4401,  1081,  1229,  2530,  6014,  7947,  5329,
        2579,  4751,  6464, 11703,  7023,  2812,  5890, 10698,
        3109,  2125,  1960, 10925, 10601, 10404,  4189,  1875,
        5847,  8546,  4615,  5190, 11324, 10578,  5882, 11155,
        8417, 12275, 10599,  7446,  5719,  3569,  5981, 10108,
        4426,  8306, 10755,  4679, 11052,  1538, 11857,   100,
        8247,  6625,  9725,  5145,  3412,  7858,  5831,  9460,
        5217, 10740,  7882,  7506, 12172, 11292,  6049,    79,
        13,  6938,  8886,  5453,  4586, 11455,  2903,  4676,
        9843,  7621,  8822,  9109,  2083,  8507,  8685,  3110,
        7015,  3269,  1367,  6397, 10259,  8435, 10527, 11559,
        11094,  2211,  1808,  7319,    48,  9547,  2560,  1228,
        9438, 10787, 11800,  1820, 11406,  8966,  6159,  3012,
        6109,  2796,  2203,  1652,   711,  7004,  1053,  8973,
        5244,  1517,  9322, 11269,   900,  3888, 11133, 10736,
        4949,  7616,  9974,  4746, 10270,   126,  2921,  6720,
        6635,  6543,  1582,  4868,    42,   673,  2240,  7219,
        1296, 11989,  7675,  8578, 11949,   989, 10541,  7687,
        7085,  8487,  1004, 10236,  4703,   163,  9143,  4597,
        6431, 12052,  2991, 11938,  4647,  3362,  2060, 11357,
        12011,  6664,  5655,  7225,  5914,  9327,  4092,  5880,
        6932,  3402,  5133,  9394, 11229,  5252,  9008,  1556,
        6908,  4773,  3853,  8780, 10325,  7737,  1758,  7103,
        11375, 12273,  8602,  3243,  6536,  7590,  8591, 11552,
        6101,  3253,  9969,  9640,  4506,  3736,  6829, 10822,
        9130,  9948,  3566,  2133,  3901,  6038,  7333,  6609,
        3468,  4659,   625,  2700,  7738,  3443,  3060,  3388,
        3526,  4418, 11911,  6232,  1730,  2558, 10340,  5344,
        5286,  2190, 11562,  6199,  2482,  8756,  5387,  4101,
        4609,  8605,  8226,   144,  5656,  8704,  2621,  5424,
        10812,  2959, 11346,  6249,  1715,  4951,  9540,  1888,
        3764,    39,  8219,  2080,  2502,  1469, 10550,  8709,
        5601,  1093,  3784,  5041,  2058,  8399, 11448,  9639,
        2059,  9878,  7405,  2496,  7918, 11594,   371,  7993,
        3073, 10326,    40, 10004,  9245,  7987,  5603,  4051,
        7894,   676, 11380,  7379,  6501,  4981,  2628,  3488,
        10956,  7022,  6737,  9933,  7139,  2330,  3884,  5473,
        7865,  6941,  5737,  5613,  9505, 11568, 11277,  2510,
        6689,   386,  4462,   105,  2076, 10443,   119,  3955,
        4370, 11505,  3672, 11439,   750,  3240,  3133,   754,
        4013, 11929,  9210,  5378, 11881, 11018,  2818,  1851,
        4966,  8181,  2688,  6205,  6814,   926,  2936,  4327,
        10175,  7089,  6047,  9410, 10492,  8950,  2472,  6255,
        728,  7569,  6056, 10432, 11036,  2452,  2811,  3787,
        945,  8998,  1244,  8815, 11017, 11218,  5894,  4325,
        4639,  3819,  9826,  7056,  6786,  8670,  5539,  7707,
        1361,  9812,  2949, 11265, 10301,  9108,   478,  6489,
        101,  1911,  9483,  3608, 11997, 10536,   812,  8915,
        637,  8159,  5299,  9128,  3512,  8290,  7068,  7922,
        3036,  4759,  2163,  3937,  3755, 11306,  7739,  4922,
        11932,   424,  5538,  6228, 11131,  7778, 11974,  1097,
        2890, 10027,  2569,  2250,  2352,   821,  2550, 11016,
        7769,   136,   617,  3157,  5889,  9219,  6855,   120,
        4405,  1825,  9635,  7214, 10261, 11393,  2441,  9562,
        11176,   599,  2085, 11465,  7233,  6177,  4801,  9926,
        9010,  4514,  9455, 11352, 11670,  6174,  7950,  9766,
        6896, 11603,  3213,  8473,  9873,  2835, 10422,  3732,
        7961,  1457, 10857,  8069,   832,  1628,  3410,  4900,
        10855,  5111,  9543,  6325,  7431,  4083,  3072,  8847,
        9853, 10122,  5259, 11413,  6556,   303,  1465,  3871,
        4873,  5813, 10017,  6898,  3311,  5947,  8637,  5852,
        3856,   928,  4933,  8530,  1871,  2184,  5571,  5879,
        3481, 11597,  9511,  8153,    35,  2609,  5963,  8064,
        1080, 12039,  8444,  3052,  3813, 11065,  6736,  8454,
        2340,  7651,  1910, 10709,  2117,  9637,  6402,  6028,
        2124,  7701,  2679,  5183,  6270,  7424,  2597,  6795,
        9222, 10837,   280,  8583,  3270,  6753,  2354,  3779,
        6102,  4732,  5926,  2497,  8640, 10289,  6107, 12127,
        2958, 12287, 10292,  8086,   817,  4021,  2610,  1444,
        5899, 11720,  3292,  2424,  5090,  7242,  5205,  5281,
        9956,  2702,  6656,   735,  2243, 11656,   833,  3107,
        6012,  6801,  1126,  6339,  5250, 10391,  9642,  5278,
        3513,  9769,  3025,   779,  9433,  3392,  7437,   668,
        10184,  8111,  6527,  6568, 10831,  6482,  8263,  5711,
        9780,   467,  5462,  4425, 11999,  1205,  5015,  6918,
        5096,  3827,  5525, 11579,  3518,  4875,  7388,  1931,
        6615,  1541,  8708,   260,  3385,  4792,  4391,  5697,
        7895,  2155,  7337,   236, 10635, 11534,  1906,  4793,
        9527,  7239,  8354,  5121, 10662,  2311,  3346,  8556,
        707,  1088,  4936,   678, 10245,    18,  5684,   960,
        4459,  7957,   226,  2451,     6,  8874,   320,  6298,
        8963,  8735,  2852,  2981,  1707,  5408,  5017,  9876,
        9790,  2968,  1899,  6729,  4183,  5290, 10084,  7679,
        7941,  8744,  5694,  3461,  4175,  5747,  5561,  3378,
        5227,   952,  4319,  9810,  4356,  3088, 11118,   840,
        6257,   486,  6000,  1342, 10382,  6017,  4798,  5489,
        4498,  4193,  2306,  6521,  1475,  6372,  9029,  8037,
        1625,  7020,  4740,  5730,  7956,  6351,  6494,  6917,
        11405,  7487, 10202, 10155,  7666,  7556, 11509,  1546,
        6571, 10199,  2265,  7327,  5824, 11396, 11581,  9722,
        2251, 11199,  5356,  7408,  2861,  4003,  9215,   484,
        7526,  9409, 12235,  6157,  9025,  2121, 10255,  2519,
        9533,  3824,  8674, 11419, 10888,  4762, 11303,  4097,
        2414,  6496,  9953, 10554,   808,  2999,  2130,  4286,
        12078,  7445,  5132,  7915,   245,  5974,  4874,  7292,
        7560, 10539,  9952,  9075,  2113,  3721, 10285, 10022,
        9578,  8934, 11074,  9498,   294,  4711,  3391,  1377,
        9072, 10189,  4569, 10890,  9909,  6923,    53,  4653,
        439, 10253,  7028, 10207,  8343,  1141,  2556,  7601,
        8150, 10630,  8648,  9832,  7951, 11245,  2131,  5765,
        10343,  9781,  2718,  1419,  4531,  3844,  4066,  4293,
        11657, 11525, 11353,  4313,  4869, 12186,  1611, 10892,
        11489,  8833,  2393,    15, 10830,  5003,    17,   565,
        5891, 12177, 11058, 10412,  8885,  3974, 10981,  7130,
        5840, 10482,  8338,  6035,  6964,  1574, 10936,  2020,
        2465,  8191,   384,  2642,  2729,  5399,  2175,  9396,
        11987,  8035,  4375,  6611,  5010, 11812,  9131, 11427,
        104,  6348,  9643,  6757, 12110,  5617, 10935,   541,
        135,  3041,  7200,  6526,  5085, 12136,   842,  4129,
        7685, 11079,  8426,  1008,  2725, 11772,  6058,  1101,
        1950,  8424,  5688,  6876, 12005, 10079,  5335,   927,
        1770,   273,  8377,  2271,  5225, 10283,   116, 11807,
        91, 11699,   757,  1304,  7524,  6451,  8032,  8154,
        7456,  4191,   309,  2318,  2292, 10393, 11639,  9481,
        12238, 10594,  9569,  7912, 10368,  9889, 12244,  7179,
        3924,  3188,   367,  2077,   336,  5384,  5631,  8596,
        4621,  1775,  8866,   451,  6108,  1317,  6246,  8795,
        5896,  7283,  3132, 11564,  4977, 12161,  7371,  1366,
        12130, 10619,  3809,  5149,  6300,  2638,  4197,  1418,
        10065,  4156,  8373,  8644, 10445,   882,  8158, 10173,
        9763, 12191,   459,  2966,  3166,   405,  5000,  9311,
        6404,  8986,  1551,  8175,  3630, 10766,  9265,   700,
        8573,  9508,  6630, 11437, 11595,  5850,  3950,  4775,
        11941,  1446,  6018,  3386, 11470,  5310,  5476,   553,
        9474,  2586,  1431,  2741,   473, 11383,  4745,   836,
        4062, 10666,  7727, 11752,  5534,   312,  4307,  4351,
        5764,  8679,  8381,  8187,     5,  7395,  4363,  1152,
        5421,  5231,  6473,   436,  7567,  8603,  6229,  8230
    ];
//}
// ==== vrfy_constants.h END =====================================================================================================================
// ==== vrfy.c BEGIN =====================================================================================================================

//import "lib_falcon_common.sol";
//import "lib_falcon_vrfy_constants.sol";

//import GMb from "lib_falcon_vrfy_constants.sol";

//library lib_falcon_vrfy
//{
/* TODO: ==>        
    //uint32 Q = 1; // TODO: Where do I get Q
    //uint32 Q0I = 1; // TODO: Where do I get Q0I
    //uint32 R = 1; // TODO: Where do I get R
    //uint32 R2 = 1; // TODO: Where do I get R2
    //uint32[2] GMb = [1,2]; // TODO: Where do I get GMb
    //uint32[2] iGMb = [1,2]; // TODO: Where do I get iGMb
TODO: <== */



    ////////////////////////////////////////
    // Addition modulo q. Operands must be in the 0..q-1 range.
    ////////////////////////////////////////
    function mq_add(uint32 x, uint32 y) private pure returns (uint32 result)
    {
        uint32    d;

        d = x + y - Q;
        d += Q & -(d >> 31);
        result = d;
    }

    ////////////////////////////////////////
    // Subtraction modulo q. Operands must be in the 0..q-1 range.
    ////////////////////////////////////////
    function mq_sub(uint32 x, uint32 y) private pure returns (uint32 result)
    {
         // As in mq_add(), we use a conditional addition to ensure the result is in the 0..q-1 range.
        uint32    d;

        d = x - y;
        d += Q & -(d >> 31);
        return d;
    }

    ////////////////////////////////////////
    // Division by 2 modulo q. Operand must be in the 0..q-1 range.
    ////////////////////////////////////////
    function mq_rshift1(uint32 x) private pure returns (uint32 result)
    {
        x += Q & -(x & 1);
        return (x >> 1);
    }

    ////////////////////////////////////////
    // Montgomery multiplication modulo q. If we set R = 2^16 mod q, then this function computes: x * y / R mod q
    // Operands must be in the 0..q-1 range.
    ////////////////////////////////////////
    function mq_montymul(uint32 x, uint32 y) private pure returns (uint32 result)
    {
        uint32    z;
        uint32    w;

        z = x * y;
        w = ((z * Q0I) & 0xFFFF) * Q;
        z = (z + w) >> 16;
        z -= Q;
        z += Q & -(z >> 31);
        return z;
    }

    ////////////////////////////////////////
    // Montgomery squaring (computes (x^2)/R).
    ////////////////////////////////////////
    function mq_montysqr(uint32 x) private pure returns (uint32 result)
    {
        return mq_montymul(x, x);
    }

    ////////////////////////////////////////
    // Divide x by y modulo q = 12289.
    ////////////////////////////////////////
    function mq_div_12289(uint32 x, uint32 y) private pure returns (uint32 result)
    {
    /*$off*/
        uint32    y0;
        uint32    y1;
        uint32    y2;
        uint32    y3;
        uint32    y4;
        uint32    y5;
        uint32    y6;
        uint32    y7;
        uint32    y8;
        uint32    y9;
        uint32    y10;
        uint32    y11;
        uint32    y12;
        uint32    y13;
        uint32    y14;
        uint32    y15;
        uint32    y16;
        uint32    y17;
        uint32    y18;
    /*$on*/

        y0 = mq_montymul(y, R2);
        y1 = mq_montysqr(y0);
        y2 = mq_montymul(y1, y0);
        y3 = mq_montymul(y2, y1);
        y4 = mq_montysqr(y3);
        y5 = mq_montysqr(y4);
        y6 = mq_montysqr(y5);
        y7 = mq_montysqr(y6);
        y8 = mq_montysqr(y7);
        y9 = mq_montymul(y8, y2);
        y10 = mq_montymul(y9, y8);
        y11 = mq_montysqr(y10);
        y12 = mq_montysqr(y11);
        y13 = mq_montymul(y12, y9);
        y14 = mq_montysqr(y13);
        y15 = mq_montysqr(y14);
        y16 = mq_montymul(y15, y10);
        y17 = mq_montysqr(y16);
        y18 = mq_montymul(y17, y0);

        return mq_montymul(y18, x);
    }

    ////////////////////////////////////////
    // Compute NTT on a ring element.
    ////////////////////////////////////////
    function mq_NTT(bytes memory /*uint16**/ a, uint32 logn) private view
    {
        uint32  n;
        uint32  t;
        uint32  m;

        n = uint32(1) << logn;
        t = n;
        for (m = 1; m < n; m <<= 1)
        {
            uint32  ht;
            uint32  i;
            uint32  j1;

            ht = t >> 1;
            j1 = 0;
            for (i = 0; i < m; i++)
            {
                uint32 j;
                uint32 j2;
                uint32 s;

                s = GMb[m + i];
                j2 = j1 + ht;
                for (j = j1; j < j2; j++)
                {
                    uint32 u;
                    uint32 v;
                    uint32 tmp32;
                    uint16 tmp16;

                    u = byte_array_uint16_get(a,j); // u = a[j];
                    tmp32 = byte_array_uint16_get(a,j + ht); // tmp = a[j + ht];
                    v = mq_montymul(tmp32, s);               // v = mq_montymul(a[j + ht], s);

                    tmp16 = uint16(mq_add(u, v));
                    byte_array_uint16_set(a,j   ,tmp16); // a[j]      = uint16(mq_add(u, v));
                    tmp16 = uint16(mq_sub(u, v));
                    byte_array_uint16_set(a,j+ht,tmp16); // a[j + ht] = uint16(mq_sub(u, v));
                }
                j1 += t;
            }

            t = ht;
        }
    }

    uint32 stackvar_mq_iNTT_n;
    uint32 stackvar_mq_iNTT_t;
    uint32 stackvar_mq_iNTT_m;
    uint32 stackvar_mq_iNTT_ni;

    ////////////////////////////////////////
    // Compute the inverse NTT on a ring element, binary case.
    ////////////////////////////////////////
    function mq_iNTT(bytes memory /*uint16**/ a, uint32 logn) public payable
    {
        stackvar_mq_iNTT_n = uint32(1) << logn;
        stackvar_mq_iNTT_t = 1;
        stackvar_mq_iNTT_m = stackvar_mq_iNTT_n;
        while (stackvar_mq_iNTT_m > 1)
        {
            uint32 hm;
            uint32 dt;
            uint32 i;
            uint32 j1;

            hm = stackvar_mq_iNTT_m >> 1;
            dt = stackvar_mq_iNTT_t << 1;
            j1 = 0;
            for (i = 0; i < hm; i++)
            {
                uint32 j;
                uint32 j2;
                uint32 s;

                j2 = j1 + stackvar_mq_iNTT_t;
                s = iGMb[hm + i];
                for (j = j1; j < j2; j++)
                {
                    uint32 u;
                    uint32 v;
                    uint32 w;
                    uint16 tmp16;

                    u = byte_array_uint16_get(a,j  ); // u = a[j];
                    v = byte_array_uint16_get(a,j+stackvar_mq_iNTT_t); // v = a[j + t];
                    tmp16 = uint16(mq_add(u, v));
                    byte_array_uint16_set(a,j,tmp16); // a[j] = uint16(mq_add(u, v));

                    w = mq_sub(u, v);
                    tmp16 = uint16(mq_montymul(w, s));
                    byte_array_uint16_set(a,j+stackvar_mq_iNTT_t,tmp16); // a[j + t] = uint16(mq_montymul(w, s));
                }
                j1 += dt;
            }

            stackvar_mq_iNTT_t = dt;
            stackvar_mq_iNTT_m = hm;
        }

        stackvar_mq_iNTT_ni = R;
        for (stackvar_mq_iNTT_m = stackvar_mq_iNTT_n; stackvar_mq_iNTT_m > 1; stackvar_mq_iNTT_m >>= 1)
        {
            stackvar_mq_iNTT_ni = mq_rshift1(stackvar_mq_iNTT_ni);
        }

        for (stackvar_mq_iNTT_m = 0; stackvar_mq_iNTT_m < stackvar_mq_iNTT_n; stackvar_mq_iNTT_m++)
        {
            uint16 tmp1 = byte_array_uint16_get(a, stackvar_mq_iNTT_m); // a[m];
            uint16 tmp2 = uint16(mq_montymul(tmp1, stackvar_mq_iNTT_ni));
            byte_array_uint16_set(a,stackvar_mq_iNTT_m,tmp2); // a[j + t] = uint16(mq_montymul(w, s));
        }
    }

    ////////////////////////////////////////
    // Convert a polynomial (mod q) to Montgomery representation.
    ////////////////////////////////////////
    function mq_poly_tomonty(bytes memory /*uint16**/ f, uint32 logn) private pure
    {
        uint32  u;
        uint32  n;

        n = uint32(1) << logn;
        for (u = 0; u < n; u++)
        {
            uint16 tmp1 = byte_array_uint16_get(f,u); // f[u];
            uint16 tmp2 = uint16(mq_montymul(tmp1, R2));
            byte_array_uint16_set(f,u,tmp2); // f[u] = uint16(mq_montymul(f[u], R2));
        }
    }

    ////////////////////////////////////////
    // Multiply two polynomials together (NTT representation, and using
    // a Montgomery multiplication). Result f*g is written over f.
    ////////////////////////////////////////
    function mq_poly_montymul_ntt(bytes memory /*uint16**/ f, bytes memory /*uint16**/ g, uint32 logn) private pure
    {
        uint32  u;
        uint32  n;

        n = uint32(1) << logn;
        for (u = 0; u < n; u++)
        {
            uint16 tmp1 = byte_array_uint16_get(f,u);
            uint16 tmp2 = byte_array_uint16_get(g,u);
            uint16 tmp16 = uint16(mq_montymul(tmp1, tmp2));
            byte_array_uint16_set(f,u,tmp16); // f[u] = uint16(mq_montymul(f[u], g[u]));
        }
    }

    ////////////////////////////////////////
    // Subtract polynomial g from polynomial f.
    ////////////////////////////////////////
    function mq_poly_sub(bytes memory /*uint16**/ f, bytes memory /*uint16**/ g, uint32 logn) private pure
    {
        uint32  u;
        uint32  n;

        n = uint32(1) << logn;
        for (u = 0; u < n; u++)
        {
            uint16 tmp1 = byte_array_uint16_get(f,u);
            uint16 tmp2 = byte_array_uint16_get(g,u);
            uint16 tmp16 = uint16(mq_sub(tmp1, tmp2));
            byte_array_uint16_set(f,u,tmp16); // f[u] = uint16(mq_sub(f[u], g[u]));

        }
    }

    /* ===================================================================== */

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function PQCLEAN_FALCON512_CLEAN_to_ntt_monty(bytes memory /*uint16**/ h, uint32 logn) public view
    {
        //fprintf(stdout, "INFO: PQCLEAN_FALCON512_CLEAN_to_ntt_monty() ENTRY\n");
        mq_NTT(h, logn);
        mq_poly_tomonty(h, logn);
    }


    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function PQCLEAN_FALCON512_CLEAN_verify_raw(bytes memory  /*uint16**/     c0,
                                                bytes memory /*int16_t **/    s2,
                                                bytes memory  /*uint16**/     h,
                                                uint32                        logn,
                                                bytes memory workingStorage) public payable returns (int result)
    {
        uint32 u;
        uint32 n;
        bytes memory /* uint16* */ tt;

        //fprintf(stdout, "INFO: PQCLEAN_FALCON512_CLEAN_verify_raw() ENTRY\n");
        n = uint32(1) << logn;
        tt = workingStorage;  // tt = (uint16 *)workingStorage;

        // Reduce s2 elements modulo q ([0..q-1] range).
        for (u = 0; u < n; u++)
        {
            uint32 w;

            uint16 tmp1 = byte_array_uint16_get(s2,u); // w = uint32(s2[u]);
            w = uint32(tmp1);

            w += Q & -(w >> 31);
            byte_array_uint16_set(tt,u,uint16(w)); // tt[u] = uint16(w);
        }

        // Compute -s1 = s2*h - c0 mod phi mod q (in tt[]).
        mq_NTT(tt, logn);
        mq_poly_montymul_ntt(tt, h, logn);
        mq_iNTT(tt, logn);
        mq_poly_sub(tt, c0, logn);

        // Normalize -s1 elements into the [-q/2..q/2] range.
        for (u = 0; u < n; u++)
        {
            int32 w;

            uint16 tmp1 = byte_array_uint16_get(tt,u); // w = int32(tt[u]);
            w = int32(tmp1);

            w -= int32(Q & -(((Q >> 1) - uint32(w)) >> 31));
            byte_array_int16_set(tt,u,int16(w)); // tt[u] = int16(w);  // ((int16 *)tt)[u] = (int16)w;
        }

        // Signature is valid if and only if the aggregate (-s1,s2) vector is short enough.
        int rc = PQCLEAN_FALCON512_CLEAN_is_short(tt, s2, logn);

        //fprintf(stdout, "INFO: PQCLEAN_FALCON512_CLEAN_verify_raw() EXIT\n");
        return rc;
    }
//}
// ==== vrfy.c END =====================================================================================================================
// ==== pqclean.c BEGIN =====================================================================================================================

// https://manojpramesh.github.io/solidity-cheatsheet/


uint16 constant PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES = 1281;
uint16 constant PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES = 897;
uint16 constant PQCLEAN_FALCON512_CLEAN_CRYPTO_SIGNATUREBYTES = 690;

//import "falcon_sha3_c.sol";
//import * as falcon_sha3 from "lib_falcon_sha3_c.sol";
//import "falcon_sha3_c.sol" as falcon_sha3;

//library lib_falcon_pqclean
//{
    ////////////////////////////////////////
    //
    ////////////////////////////////////////

    uint16 constant NONCELEN = 40;

    // ====================================================================
    // Implementation
    // ====================================================================

    ////////////////////////////////////////
    //
    // static int do_verify(const uint8_t*  nonce,
    //                      const uint8_t*  sigbuf,
    //                      size_t          sigbuflen,
    //                      const uint8_t*  m,
    //                      size_t          mlen,
    //                      const uint8_t*  pk)
    ////////////////////////////////////////
    function do_verify ( bytes memory /* uint8_t* */ nonce,
                         bytes memory /* uint8_t* */ /*sigbuf*/,
                         uint16                      sigbuflen,
                         bytes memory /* uint8_t* */ m,
                         uint16                      mlen,
                         bytes memory /* uint8_t* */ pk        ) public payable returns (int16)
    {
        //uint8[2*512] memory workingStorage; // array of 1024 bytes
        //uint16[512]  memory h;
        //uint16[512]  memory hm;
        //int16[512]   memory sig;
        uint16        sz1;
        uint16        sz2;
        int16         rc;

        //fprintf(stdout, "INFO: do_verify() ENTRY\n");

        ///////////////////////////////////////////////
        // Validate params
        if (uint8(pk[0]) != (0x00 + 9))
        {
            return -3;
        }
        if (sigbuflen == 0)
        {
            return -5;
        }

        ///////////////////////////////////////////////
        // Decode public key.
        //fprintf(stdout, "INFO: do_verify() calling PQCLEAN_FALCON512_CLEAN_modq_decode()\n");
/* TODO: ==>        
        sz1 = PQCLEAN_FALCON512_CLEAN_modq_decode( h, 9, pk + 1, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1);
TODO: <== */
        if (sz1 != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1)
        {
            return -1;
        }

        //fprintf(stdout, "INFO: do_verify() calling PQCLEAN_FALCON512_CLEAN_to_ntt_monty()\n");
/* TODO: ==>        
        PQCLEAN_FALCON512_CLEAN_to_ntt_monty(h, 9);
TODO: <== */

        ///////////////////////////////////////////////
        // Decode signature.
        //fprintf(stdout, "INFO: do_verify() calling PQCLEAN_FALCON512_CLEAN_comp_decode()\n");
/* TODO: ==>        
        sz2 = PQCLEAN_FALCON512_CLEAN_comp_decode(sig, 9, sigbuf, sigbuflen);
TODO: <== */
        if (sz2 != sigbuflen)
        {
            return -6;
        }

        ///////////////////////////////////////////////
        // Hash nonce + message into a vector.
        OQS_SHA3_shake256_inc_init();
        OQS_SHA3_shake256_inc_absorb(nonce, NONCELEN);
        OQS_SHA3_shake256_inc_absorb(m, mlen);
        OQS_SHA3_shake256_inc_finalize();
/* TODO: ==>        
        PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(hm, 9, workingStorage);
TODO: <== */
        OQS_SHA3_shake256_inc_ctx_release();

        ///////////////////////////////////////////////
        // Verify signature.
        //fprintf(stdout, "INFO: do_verify() calling PQCLEAN_FALCON512_CLEAN_verify_raw()\n");
/* TODO: ==>        
        rc = PQCLEAN_FALCON512_CLEAN_verify_raw(hm, sig, h, 9, workingStorage);
TODO: <== */
        if (rc == 0)
        {
            return -7;
        }

        //fprintf(stdout, "INFO: do_verify() EXIT\n");
        return 0;
    }


    ////////////////////////////////////////
    //
    // int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(const uint8_t*  sig,
    //                                                size_t          siglen,
    //                                                const uint8_t*  m,
    //                                                size_t          mlen,
    //                                                const uint8_t*  pk)
    ////////////////////////////////////////
    function PQCLEAN_FALCON512_CLEAN_crypto_sign_verify ( bytes memory /* uint8_t* */ sig,
                                                          uint16                      siglen,
                                                          bytes memory /* uint8_t* */ /*m*/,
                                                          uint16                      /*mlen*/,
                                                          bytes memory /* uint8_t* */ /*pk*/     ) public pure  returns (int16)
    {
        if (siglen < 1 + NONCELEN) // 1 + 40
        {
            return -11;
        }

        if (uint8(sig[0]) != (0x30 + 9))
        {
            return -12;
        }

        uint ii;
        uint sourceOffset;
        uint8[NONCELEN]  memory nonce;
        uint32 sigbuflen = siglen - 1 - NONCELEN;
        //uint8[sigbuflen] storage sigbuf;
        uint8[g_SIGBUFLEN] memory sigbuf;
        int16 retval;

        sourceOffset = 1;
        for (ii=0; ii<NONCELEN; ii++)
        {
            nonce[ii] = uint8(sig[sourceOffset + ii]);
        }

        sourceOffset = 1 + NONCELEN;
        for (ii=0; ii<sigbuflen; ii++)
        {
            sigbuf[ii] = uint8(sig[sourceOffset + ii]);
        }

        //fprintf(stdout, "INFO: PQCLEAN_FALCON512_CLEAN_crypto_sign_verify() Calling do_verify()\n");
/* TODO: ==>        
        retval = do_verify(nonce, sigbuf, uint16(sigbuflen), m, mlen, pk);
TODO: <== */

        return retval;
    }
//}
// ==== pqclean.c END =====================================================================================================================

// ==== falcon_dataset_from_kestrel.h BEGIN =====================================================================================================================

//contract lib_falcon_dataset_from_kestrel
//{

    // "Falcon512VerifyTest_Signature.txt"
    // Size = 658 (0x292) bytes
    // The 1st byte of the signature (0x39 = 00111001 = 0cc1nnnn) is telling us that...
    //   a) cc is 01 (i.e. Encoding uses the compression algorithm described in Section 3.11.2)
    //   b) nnnn is 1001 (9)
    uint32 constant g_signatureLen = 658;
    uint32 constant g_SIGBUFLEN = g_signatureLen - 1 - NONCELEN;
    uint8[658] g_signature =
    [
        // 0-----1-----2-----3-----4-----5-----6-----7-----8-----9----10-----1-----2-----3-----4-----5-----6-----7-----8-----9----20-----1-----2-----3-----4-----5-----6-----7-----8-----9----30-----1
        // SignatureType [1]
        0x39,
        // Nonce [40]
              0x01, 0x91, 0xEF, 0x48, 0x48, 0x6E, 0xB9, 0xD9, 0xA6, 0x82, 0x3D, 0x8E, 0x6F, 0xF0, 0xD7, 0xF4, 0xDF, 0x8B, 0xED, 0x13, 0xAF, 0x7F, 0xA5, 0x5A, 0x7E, 0x8D, 0xFA, 0x0D, 0x19, 0x72, 0x58,
        0x42, 0xA5, 0x45, 0x1B, 0xCF, 0x4C, 0x06, 0x19, 0x82,
        // Actual Signature [658 - 1 - 40 = 617]
                                                              0xD0, 0x21, 0xC6, 0x3A, 0x7D, 0x66, 0x6C, 0x20, 0x24, 0xFE, 0x57, 0x03, 0x3B, 0x1A, 0x1B, 0xDA, 0x8C, 0x21, 0x79, 0xC5, 0x18, 0xC9, 0x4D,
        0x43, 0x49, 0x47, 0xEA, 0xCC, 0x10, 0x9E, 0xFE, 0x79, 0x28, 0x57, 0xFF, 0x64, 0x50, 0xCC, 0x85, 0x3E, 0x8B, 0xB9, 0xD5, 0xD9, 0x51, 0xB3, 0xDD, 0xB1, 0x39, 0x7F, 0xAD, 0xC2, 0x21, 0x07, 0x62,
        0xB4, 0x79, 0xE3, 0x86, 0xE6, 0x60, 0xA6, 0x8E, 0xB2, 0xAD, 0x03, 0x4A, 0x58, 0xA3, 0xD0, 0xCC, 0xE2, 0x37, 0x0E, 0xDF, 0x25, 0x7F, 0xF4, 0xF8, 0x1F, 0xE9, 0x7C, 0x9B, 0xB1, 0x0C, 0x1A, 0x96,
        0xEE, 0x87, 0xD2, 0x41, 0x4F, 0xDF, 0x4E, 0xA3, 0x9F, 0x9F, 0x7C, 0x06, 0x04, 0xD1, 0xA3, 0xAE, 0xBE, 0x5D, 0x73, 0xA6, 0xA1, 0xF7, 0x22, 0x1A, 0x99, 0xEB, 0x23, 0x89, 0xB9, 0x05, 0xDA, 0x94,
        0x76, 0x6C, 0xD2, 0x7A, 0x9A, 0x89, 0xF1, 0x3D, 0x56, 0xB9, 0x7C, 0xDD, 0x34, 0x66, 0x89, 0xCF, 0xC5, 0xB3, 0xBD, 0xBB, 0xDC, 0x51, 0x02, 0xD3, 0xB5, 0xF9, 0x3A, 0x2A, 0x95, 0xBE, 0x40, 0xAF,
        0xCA, 0xAC, 0x41, 0x6D, 0x83, 0x13, 0x91, 0x47, 0x4C, 0x22, 0x98, 0xDA, 0x0A, 0x35, 0x9B, 0xC9, 0x58, 0xA5, 0xF2, 0x27, 0xDE, 0x99, 0x1A, 0x33, 0x89, 0x44, 0xD6, 0xEB, 0xE4, 0x96, 0x3F, 0x1A,
        0x4B, 0xA5, 0xBB, 0x3D, 0x5C, 0x67, 0x25, 0x26, 0x99, 0x23, 0x29, 0xC8, 0x4C, 0x57, 0x70, 0xC0, 0x3A, 0x5E, 0x43, 0x50, 0x4A, 0x28, 0xFA, 0x86, 0xF3, 0xB9, 0xBD, 0x72, 0x35, 0x4C, 0x0B, 0x19,
        0x21, 0xD1, 0xB5, 0x68, 0xE5, 0x21, 0x28, 0x56, 0xD8, 0x43, 0x6F, 0x79, 0xA8, 0xC4, 0x09, 0xE6, 0x31, 0x08, 0x2A, 0x4E, 0x28, 0xB7, 0xCB, 0x99, 0xD8, 0x9C, 0x2A, 0x9A, 0xB3, 0xC1, 0x96, 0xC5,
        0x6A, 0x77, 0xE6, 0xD0, 0x57, 0x18, 0x19, 0x6B, 0x31, 0x6D, 0x8E, 0x9B, 0xED, 0xCF, 0xC2, 0x14, 0xE2, 0xA3, 0x3C, 0x02, 0xF0, 0xAF, 0xD8, 0x21, 0xDB, 0xFC, 0xB9, 0x66, 0xC8, 0xBB, 0x8D, 0xDE,
        0x01, 0xC8, 0x12, 0xA2, 0x04, 0x5B, 0x6B, 0xC8, 0xDE, 0x76, 0x7F, 0x97, 0xB7, 0x39, 0xDC, 0x8E, 0xD2, 0x62, 0xF4, 0x3D, 0xFC, 0x09, 0x2E, 0x49, 0xF3, 0x4C, 0x77, 0x28, 0x83, 0x98, 0x95, 0xE4,
        0x62, 0x06, 0x20, 0xE4, 0xA1, 0x93, 0xE9, 0x4D, 0xBF, 0x2A, 0x9D, 0x43, 0x9E, 0x24, 0x9E, 0x6E, 0xC3, 0x37, 0x7E, 0xD6, 0x73, 0x40, 0x30, 0xAC, 0xD4, 0x3D, 0x13, 0x8B, 0x98, 0x2C, 0x36, 0xDF,
        0x81, 0x4A, 0x42, 0x57, 0xF9, 0x71, 0xA5, 0x3A, 0xA5, 0xD9, 0x2A, 0x76, 0x70, 0x91, 0x54, 0x69, 0x01, 0x3E, 0x68, 0x12, 0x4E, 0xDA, 0xE3, 0xFC, 0x11, 0xB4, 0xCA, 0x47, 0x09, 0x38, 0xEE, 0x2F,
        0x21, 0x8B, 0xC0, 0xE1, 0x14, 0x68, 0xA6, 0x09, 0x2F, 0x23, 0x3D, 0xE9, 0x14, 0x79, 0x0C, 0x97, 0x2F, 0x77, 0xD9, 0x5F, 0x96, 0x8A, 0xC5, 0xF6, 0xE0, 0x96, 0x8E, 0x0E, 0xFA, 0x8D, 0x62, 0x88,
        0x25, 0xF3, 0xFB, 0xAD, 0x22, 0x54, 0xE0, 0x4E, 0x9B, 0xA3, 0x4D, 0xEF, 0xC6, 0x98, 0xB2, 0xE1, 0x9E, 0x96, 0x29, 0x29, 0x0F, 0x4E, 0x56, 0x82, 0x27, 0x05, 0x95, 0x03, 0x5B, 0x07, 0x40, 0x4B,
        0x09, 0x1F, 0x53, 0x25, 0x29, 0x3E, 0xD4, 0x02, 0x1C, 0x61, 0x9D, 0x7F, 0x09, 0x14, 0xAC, 0x47, 0x21, 0x9B, 0x9E, 0x5D, 0xF6, 0xFD, 0xA5, 0xAC, 0xBB, 0x39, 0x8A, 0xDB, 0x5C, 0x85, 0x40, 0xDC,
        0x33, 0x90, 0xA5, 0x48, 0xD8, 0x2B, 0xE4, 0x2F, 0xAC, 0x8F, 0x6E, 0xF9, 0x96, 0x35, 0x46, 0xBC, 0xF2, 0x78, 0xE6, 0x3F, 0xDD, 0x49, 0xD0, 0xAB, 0xBE, 0x62, 0x20, 0x8E, 0x39, 0x56, 0x46, 0x87,
        0x71, 0xDF, 0x4A, 0x50, 0xDD, 0x7A, 0x3A, 0xA1, 0x97, 0xD8, 0x1F, 0x58, 0xC1, 0x44, 0x25, 0xEE, 0x16, 0x6D, 0x29, 0xAE, 0xF3, 0xEB, 0x2C, 0x17, 0x1F, 0xF9, 0xB2, 0x4F, 0x57, 0x5E, 0x0A, 0xE9,
        0xA6, 0x52, 0x27, 0xD1, 0xE5, 0x7A, 0xB6, 0xC5, 0xDF, 0x11, 0xA3, 0x69, 0x64, 0x5D, 0xAC, 0x71, 0x7A, 0xB6, 0x71, 0xA4, 0xC1, 0x0A, 0xEF, 0x72, 0x82, 0x41, 0x34, 0xD0, 0xE6, 0x86, 0x76, 0xBB,
        0x13, 0x8C, 0xA2, 0x0E, 0xB5, 0xE0, 0x8A, 0x0D, 0x1F, 0x90, 0xEE, 0x48, 0xAF, 0x1C, 0xCE, 0x1F, 0x21, 0xC7, 0x23, 0x94, 0xAC, 0x42, 0x7F, 0x38, 0x2C, 0xED, 0x54, 0x51, 0x83, 0x68, 0x9C, 0xDB,
        0x72, 0xCE, 0xC8, 0xEA, 0x30, 0xC7, 0x73, 0x89, 0xA1, 0x62, 0x04, 0x35, 0x62, 0x59, 0xE4, 0xB1, 0x14, 0x2D
    ];

    // "Falcon512VerifyTest_PublicKey.txt"
    // Size = 897 (0x381) bytes
    // The 1st byte of the publicKey (0x09 = 00001001 = 0000nnnn) is telling us that...
    //   a) nnnn is 1001 (9)

    // Ensure that the least significant nybble of pubKey[0] (logn) is in the range 1..10
    //     1st byte = 0cc1nnnn, where nnnn = logn
    //     1st byte = 09, so logn = 9
    // Length check:
    //     if (logn <= 1)
    //        return uint16(4) + 1;
    //     else
    //        return (uint16(7) << ((logn) - 2)) + 1;
    //     logn = 9, so we must use the else calculation
    //     7 = (0000 0000 0000 0111)
    //     logn-2 = 7
    //     (0000 0000 0000 0111) << 7 = (0000 0011 1000 0000) = 0x0380
    //     0x0380 + 1 = 0x0381 = 897
    //     i.e. Length is good
    uint32 constant g_pubKeyLen = 897;
    uint8[897] g_pubKey =
    [
        // 0-----1-----2-----3-----4-----5-----6-----7-----8-----9----10-----1-----2-----3-----4-----5-----6-----7-----8-----9----20-----1-----2-----3-----4-----5-----6-----7-----8-----9----30-----1
        0xD8, 0x75, 0x5E, 0x9F, 0x1F, 0xD2, 0x05, 0x64, 0x76, 0x25, 0x85, 0xBA, 0xA5, 0xA4, 0xF1, 0x65, 0xEB, 0xEC, 0x6D, 0xF8, 0x0A, 0xB5, 0x24, 0x8A, 0x22, 0xBB, 0xA9, 0x40, 0xA7, 0x75, 0x4A, 0xBE,
        0x53, 0x29, 0xB5, 0xC6, 0x03, 0x45, 0xF3, 0x95, 0xAD, 0x2A, 0x33, 0xAC, 0x10, 0x6E, 0x65, 0xF1, 0x4B, 0x91, 0xD0, 0xDC, 0xA3, 0x08, 0xAE, 0x4C, 0xC6, 0xDB, 0x5F, 0xE6, 0x9E, 0xEE, 0x9F, 0xE4,
        0xA3, 0x92, 0xFF, 0x64, 0xF5, 0x28, 0x65, 0x07, 0x0E, 0xB5, 0x58, 0x7E, 0x7F, 0x83, 0xAB, 0x6C, 0x18, 0x7C, 0xC0, 0x58, 0x4B, 0x35, 0x52, 0x92, 0x0A, 0x3D, 0x4B, 0x50, 0xAB, 0x0A, 0x4A, 0x1E,
        0x8D, 0x9D, 0xEA, 0x3D, 0x4B, 0x5E, 0xB0, 0x15, 0xA2, 0xF4, 0xAB, 0x59, 0xAE, 0x3D, 0x0A, 0xD2, 0xC0, 0x81, 0xD8, 0xD2, 0x42, 0x8A, 0x83, 0x80, 0x6D, 0xE7, 0x97, 0x3E, 0xC6, 0x59, 0x75, 0xFF,
        0x8F, 0xD7, 0x28, 0x7C, 0x64, 0x2B, 0x6A, 0x83, 0x25, 0x02, 0x55, 0xB6, 0x18, 0x38, 0xCB, 0x4D, 0x68, 0xC5, 0x26, 0x00, 0xB8, 0xC5, 0x33, 0x0F, 0xCE, 0x48, 0xAA, 0xEB, 0x80, 0x6D, 0x4F, 0xB9,
        0x9A, 0x9A, 0xDD, 0x5E, 0x56, 0x57, 0x74, 0x54, 0xA5, 0xA5, 0xAD, 0x56, 0x99, 0x71, 0x1D, 0xD0, 0x48, 0x54, 0xBF, 0x11, 0x48, 0x47, 0x13, 0xDE, 0xA5, 0xD9, 0xAB, 0xD1, 0x7F, 0x92, 0x14, 0xC3,
        0x3C, 0x4F, 0x4D, 0x47, 0xA6, 0x60, 0x0B, 0xC2, 0x41, 0x01, 0x1F, 0x52, 0xE2, 0x9D, 0x98, 0x20, 0xAC, 0x85, 0xAB, 0x70, 0xDF, 0xCC, 0xB1, 0xD0, 0x8C, 0x00, 0x3B, 0x48, 0x9C, 0x08, 0x26, 0xBF,
        0x28, 0xCC, 0xEE, 0x71, 0x94, 0x56, 0x37, 0xB7, 0x16, 0x1E, 0x6A, 0x99, 0x58, 0x44, 0x51, 0xBF, 0x83, 0x51, 0xA4, 0x3A, 0x0B, 0x07, 0x55, 0xCE, 0x30, 0x44, 0xF0, 0x84, 0x0B, 0x7A, 0xD0, 0x48,
        0x9E, 0x65, 0x72, 0xC8, 0x96, 0x66, 0x64, 0x63, 0xE2, 0xCF, 0xC8, 0xEB, 0xE1, 0x25, 0x8E, 0x3A, 0x96, 0x3A, 0xB1, 0x43, 0x3B, 0x17, 0x38, 0x65, 0x70, 0x5C, 0x15, 0xF0, 0x44, 0xBC, 0xFD, 0xE1,
        0xB7, 0x80, 0xD2, 0x9E, 0x42, 0x26, 0x04, 0xA9, 0x08, 0x1D, 0x23, 0x49, 0xF6, 0xD6, 0xB4, 0x06, 0x71, 0xB7, 0xC6, 0xAE, 0x77, 0xF4, 0x4C, 0x16, 0xA2, 0x24, 0x12, 0xE9, 0xE3, 0x2C, 0xB1, 0x16,
        0x36, 0x3D, 0x99, 0xCA, 0x4D, 0x2C, 0x3A, 0xCE, 0x67, 0x30, 0xFD, 0x45, 0xFC, 0x66, 0x12, 0xD3, 0x89, 0xED, 0xCD, 0x1C, 0x9B, 0x22, 0x01, 0xBA, 0x32, 0xA4, 0x70, 0x5F, 0xAC, 0x61, 0x00, 0x5E,
        0x18, 0x4B, 0x89, 0xA4, 0xC9, 0x09, 0x83, 0xAC, 0xD7, 0xAF, 0xEE, 0x69, 0x4A, 0xC9, 0xD9, 0x04, 0x47, 0x3E, 0xB5, 0x12, 0xEC, 0x2D, 0x48, 0x75, 0xC1, 0xC9, 0x54, 0xB7, 0x91, 0x50, 0x6F, 0x02,
        0xC9, 0xE6, 0x5F, 0x5D, 0x04, 0x97, 0x6E, 0xA4, 0xE8, 0x1D, 0x22, 0xD4, 0x88, 0x4E, 0xB1, 0xC4, 0x7E, 0xEB, 0x1A, 0x7E, 0xE1, 0x09, 0xE1, 0x2E, 0x61, 0xCE, 0x0E, 0xE4, 0xDF, 0xA8, 0x8F, 0xDA,
        0xCB, 0x78, 0xED, 0x61, 0xB0, 0xA3, 0x27, 0xC2, 0x06, 0x9D, 0x8C, 0xD3, 0x3D, 0x18, 0x4E, 0x68, 0xA6, 0x0C, 0x22, 0xF6, 0x80, 0x4F, 0xAC, 0xEC, 0xA9, 0x68, 0xCF, 0x5C, 0x1C, 0x27, 0x6C, 0x7D,
        0x16, 0x38, 0x6F, 0x38, 0xBB, 0x82, 0xD5, 0xEA, 0x1E, 0x11, 0xD8, 0x01, 0xF5, 0xEF, 0x33, 0xD3, 0xA3, 0xB0, 0x17, 0x1D, 0xC8, 0x70, 0x74, 0x1C, 0xE8, 0x37, 0x3C, 0x77, 0x9A, 0xE8, 0x93, 0x52,
        0x11, 0x34, 0x8C, 0x43, 0x62, 0x85, 0x70, 0x36, 0x81, 0xF1, 0xE6, 0xB0, 0xAD, 0xC0, 0x5C, 0x35, 0xC5, 0x61, 0x96, 0xC2, 0x46, 0x73, 0x1E, 0xE2, 0xA4, 0xA9, 0x98, 0xEF, 0x91, 0x8A, 0x16, 0x50,
        0x23, 0xA7, 0x6D, 0x32, 0x4C, 0x58, 0x41, 0x9C, 0xD9, 0xE7, 0x6E, 0xBC, 0xA0, 0xE1, 0x38, 0x23, 0xD9, 0x0B, 0x2E, 0xBC, 0x64, 0x17, 0x17, 0xB4, 0x04, 0xE2, 0xEE, 0x29, 0x37, 0xD4, 0x8B, 0x38,
        0x44, 0x1E, 0x88, 0xF1, 0x08, 0x6C, 0x15, 0xC9, 0x5D, 0xE8, 0xA4, 0x86, 0x32, 0xBE, 0xE5, 0xFB, 0x56, 0xF9, 0x9F, 0x07, 0xAC, 0x31, 0x03, 0x73, 0x23, 0x00, 0x03, 0x17, 0xC2, 0x91, 0xE2, 0xEA,
        0xCE, 0x78, 0x65, 0xEC, 0xE2, 0x35, 0x48, 0xE8, 0x04, 0x67, 0x92, 0x41, 0xF1, 0x36, 0x67, 0x48, 0xB1, 0x65, 0x6C, 0xD5, 0x8C, 0x28, 0xB8, 0x6D, 0x5E, 0x08, 0xE2, 0x69, 0xD0, 0xE3, 0xA6, 0x68,
        0xA8, 0x34, 0xF4, 0x17, 0x8A, 0x18, 0x8D, 0xD6, 0x33, 0x84, 0x04, 0x27, 0x73, 0xFA, 0xC1, 0x0B, 0x3D, 0x96, 0xF5, 0x33, 0xEC, 0xAB, 0xE3, 0xA8, 0xA2, 0x7E, 0x09, 0x1D, 0x58, 0x46, 0xD6, 0xEA,
        0xD8, 0xAC, 0x92, 0x41, 0x43, 0x72, 0x40, 0xAD, 0x4F, 0x7D, 0x27, 0x4B, 0x78, 0x40, 0x34, 0x02, 0x21, 0x0A, 0xD0, 0x42, 0xDD, 0xF7, 0x3D, 0x59, 0xE0, 0x2A, 0xBF, 0x65, 0x7A, 0xA4, 0x1E, 0x10,
        0x14, 0x55, 0xDF, 0x63, 0x8D, 0x44, 0xC1, 0x81, 0xE4, 0xCA, 0x21, 0x9F, 0x2C, 0x66, 0x79, 0x08, 0x8F, 0xF1, 0x1A, 0xF4, 0x39, 0x11, 0x5D, 0x8E, 0xF3, 0x8F, 0x36, 0x14, 0xB9, 0x57, 0xE1, 0xEB,
        0xB9, 0xCC, 0x2E, 0x6B, 0xEE, 0x0C, 0x06, 0x64, 0xDA, 0x7B, 0xA3, 0xF1, 0x26, 0x84, 0x04, 0xA5, 0xBA, 0xC8, 0xED, 0x45, 0x85, 0x48, 0x81, 0x97, 0x23, 0x82, 0x90, 0x88, 0x61, 0xCC, 0x7F, 0x14,
        0xF5, 0xD0, 0x3B, 0x11, 0x22, 0x73, 0x91, 0x78, 0x54, 0x61, 0x75, 0x90, 0xAA, 0xD7, 0x0E, 0xEE, 0xDF, 0x39, 0x8C, 0xB2, 0x06, 0xFF, 0x5C, 0x7F, 0x7A, 0x9C, 0x53, 0x90, 0xDF, 0xA2, 0x7E, 0x14,
        0xB1, 0x14, 0x85, 0x18, 0x83, 0x3B, 0x33, 0x75, 0xCD, 0xFA, 0xF5, 0xA7, 0x36, 0x80, 0xCD, 0xD7, 0xD0, 0xEA, 0x5F, 0x66, 0x46, 0x72, 0xFE, 0x91, 0xAE, 0x67, 0x00, 0x03, 0x2A, 0x3E, 0xE2, 0x1A,
        0xEB, 0x3A, 0xB7, 0xB6, 0xA0, 0xF6, 0x6B, 0x0F, 0x65, 0x59, 0x7A, 0x7F, 0xB6, 0xF5, 0xC1, 0xA9, 0xB1, 0x45, 0x9D, 0x48, 0x88, 0x5D, 0xB3, 0x73, 0x4A, 0xBE, 0xC9, 0x91, 0x8C, 0x0F, 0x3A, 0x81,
        0x35, 0xBB, 0xB2, 0x27, 0x99, 0x84, 0xA0, 0x54, 0x11, 0x5E, 0x9C, 0x12, 0xA8, 0xF1, 0x0C, 0xA2, 0x5B, 0x93, 0xBE, 0x8A, 0x3A, 0xCF, 0xB9, 0x4D, 0xC6, 0xA9, 0x0D, 0x4D, 0xA0, 0xE0, 0xA7, 0xAD,
        0xA8
    ];

    // "Falcon512VerifyTest_Message.txt"
    // Size = 100 (0x64) bytes
    // 100 bytes of random data
    uint32 constant g_messageLen = 100;
    uint8[100] g_message =
    [
        // 0-----1-----2-----3-----4-----5-----6-----7-----8-----9----10-----1-----2-----3-----4-----5-----6-----7-----8-----9----20-----1-----2-----3-----4-----5-----6-----7-----8-----9----30-----1
        0x36, 0xEA, 0x37, 0x8A, 0x89, 0x29, 0x4F, 0x83, 0x9D, 0xC9, 0xBC, 0xD9, 0xA8, 0x25, 0x1F, 0x92, 0xCF, 0xD3, 0x9A, 0xAC, 0xC1, 0xE2, 0x28, 0xF4, 0x44, 0x42, 0xE9, 0x5B, 0x3C, 0x59, 0xEF, 0x90,
        0x46, 0x13, 0xEC, 0xE9, 0xD3, 0x12, 0x02, 0x8B, 0x07, 0xA3, 0xCB, 0x26, 0xB3, 0xC9, 0x84, 0x4D, 0xCD, 0xB2, 0x69, 0x92, 0x99, 0xD7, 0xD4, 0x7F, 0xD6, 0x3F, 0x78, 0x89, 0xD6, 0xC5, 0xCE, 0x34,
        0x62, 0x6B, 0x58, 0x3A
    ];

//}
// ==== falcon_dataset_from_kestrel.h END =====================================================================================================================

// ==== test_sig.c BEGIN =====================================================================================================================
//import "lib_falcon_pqclean.sol";
//import "lib_falcon_dataset_from_kestrel.sol"

//contract con_falcon_test_sig
//{
    bool constant TEST_HAPPY_PATH   = true;
    bool constant TEST_UNHAPPY_PATH = true;

    int8 constant EXIT_SUCCESS = 0;
    int8 constant EXIT_FAILURE = -1;

    // OQS_STATUS;
    int8 constant OQS_ERROR                       = -1;
    int8 constant OQS_SUCCESS                     = 0;
    int8 constant OQS_EXTERNAL_LIB_ERROR_OPENSSL  = 50;

    //#ifdef TEST_UNHAPPY_PATH
    function CorruptSomeBits(bytes memory /* unsigned char **/ pData, uint16 cbData) private pure
    {
        // TODO - Any corruption will do
        //if (cbData >   0) { pData[  0] = ~(pData[  0]); }
        //if (cbData >  10) { pData[ 10] = ~(pData[ 10]); }
        //if (cbData > 100) { pData[100] = ~(pData[100]); }
    }
    //#endif


    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function main() public pure returns (int16)
    {
        //uint8[]  storage public_key;
        uint32           public_key_len = 0;
        //uint8[]  storage message;
        //uint32           message_len = 0;
        //uint8[]  storage signature;
        //uint32           signature_len;
        int16            rc;
        int8             ret = EXIT_FAILURE;

        //printf("*** ================================================================================\n");
        //printf("*** Sample computation for signature Falcon-512\n");
        //printf("*** ================================================================================\n");

        for(;;)
        {
/* TODO: ==>        
            public_key     = g_pubKey;
            public_key_len = g_pubKeyLen;
            message        = g_message;
            message_len    = g_messageLen;
            signature      = g_signature;
            signature_len  = g_signatureLen;
TODO: <== */

            if (public_key_len != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES)
            {
                //fprintf(stderr, "ERROR: Length of Public key (%lu) not as expected (%u)\n", public_key_len, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES);
                ret = EXIT_FAILURE;
                break;
            }

            if (TEST_HAPPY_PATH)
            {
                //fprintf(stdout, "-------------------------------------------------------------------------------------\n");
                //fprintf(stdout, "*** Calling PQCLEAN_FALCON512_CLEAN_crypto_sign_verify()\n");
/* TODO: ==>        
                rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(signature, signature_len, message, message_len, public_key);
TODO: <== */
                if (rc != OQS_SUCCESS)
                {
                    //fprintf(stderr, "ERROR: PQCLEAN_FALCON512_CLEAN_crypto_sign_verify failed\n");
                    ret = EXIT_FAILURE;
                    break;
                }
            }

            if (TEST_UNHAPPY_PATH)
            {
                //fprintf(stdout, "*** -------------------------------------------------------------------------------------\n");

/* TODO: ==>        
                //fprintf(stdout, "*** Modify the signature to invalidate it\n");
                CorruptSomeBits(signature, signature_len); // Modify the signature in order to invalidate it and force a failure
TODO: <== */

/* TODO: ==>        
                //fprintf(stdout, "*** Calling PQCLEAN_FALCON512_CLEAN_crypto_sign_verify()\n");
                rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(signature, signature_len, message, message_len, public_key);
TODO: <== */
                if (rc != OQS_ERROR)
                {
                    //fprintf(stderr, "ERROR: PQCLEAN_FALCON512_CLEAN_crypto_sign_verify should have failed!\n");
                    ret = EXIT_FAILURE;
                    break;
                }
            }

            //fprintf(stdout, "*** All tests pass OK\n");
            ret = EXIT_SUCCESS;
            break;
        }

        //fprintf(stdout, "*** Cleanup...\n");
        return ret;
    }
}

// ==== test_sig.c END =====================================================================================================================


