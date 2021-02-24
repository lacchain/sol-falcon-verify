const fs = require('fs');
const readline = require('readline');
const Test = require('mocha/lib/test');
const falcConsts = require('./falcon_constants.js');
const Falcon = artifacts.require("Falcon");

contract("Falcon", accounts => {

    const suite = describe("Known Answer Tests", async () => {
  
      before(async () => {
        const kats = await parseKats(fs.createReadStream('test/falcon512-KAT.rsp'));
        const falcon = await Falcon.deployed();

        kats.slice(0, 3).forEach(kat => {
          suite.addTest(new Test(`KAT test ${kat.count}`, async() => {
            const nistSignatureBuffer = Buffer.from(kat.sm, 'hex');

            const messageLength = parseInt(kat.mlen);

            const signatureBuffer = nistSignatureBuffer.slice(2 + 40 + messageLength); // skip 2 bytes for signature size + 40 bytes for nonce + message length
            const signatureLength = nistSignatureBuffer.readInt16BE(0);
            const messageBuffer = Buffer.from(kat.msg, 'hex');
            const publicKeyBuffer = Buffer.from(kat.pk, 'hex');

            //console.log('signature[%d]: %s\nmessage[%d]: %s\npk[897]: %s', signatureLength, signatureBuffer.toString('hex'), messageLength, messageBuffer.toString('hex'), publicKeyBuffer.toString('hex'));

            const contractReturn = await falcon.verify.call(1, Array.from(signatureBuffer), signatureLength, Array.from(messageBuffer), messageLength, Array.from(publicKeyBuffer), 897);
            const falconReturn = getFalconReturnValue(contractReturn);
            assert.equal(falconReturn, 0, `${falcConsts.FALCON_ERR_LongDescription[Math.abs(falconReturn)]}`);
          }));
        });
      });

      it("dummy", () => {
        // needed b/c without al least one explicit declaration mocha ignores the whole suite
      });

      const parseKats = async (katStream) =>  {
        const rl = readline.createInterface({
          input: katStream,
          crlfDelay: Infinity
        });
        let kats = [];
        let kat = {};
        for await (const line of rl) {
          if (line.startsWith("#")) {
            continue;
          }
          if (line.length === 0) {
            if (Object.keys(kat).length !== 0) {
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

      const getFalconReturnValue = (ret) => {
        var isNegative = false;
        if (ret < 0) {
          isNegative = true;
          ret = Math.abs(ret);
        }
        var remainder = ret % 10;
        if (isNegative)
          remainder = -remainder;
        return remainder;
      }
      const getReasonCode = (ret) => {
        var isNegative = false;
        if (ret < 0) {
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
