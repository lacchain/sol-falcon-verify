const fs = require('fs');
const readline = require('readline');
const Test = require('mocha/lib/test');
const Falcon = artifacts.require("Falcon");

contract("Falcon", accounts => {

    const suite = describe("Known Answer Tests", async () => {
  
      before(async () => {
        const kats = await parseKats(fs.createReadStream('test/falcon512-KAT.rsp'));
        const falcon = await Falcon.deployed();

        kats.slice(0, 3).forEach(kat => {
          suite.addTest(new Test(`${kat.count}`, async() => {
            const contractReturn = await falcon.verify.call(0, Buffer.from(kat.sm, 'hex').toJSON().data, kat.smlen, Buffer.from(kat.msg, 'hex').toJSON().data, kat.mlen, Buffer.from(kat.pk, 'hex').toJSON().data, 897);
            assert.equal(getFalconReturnValue(contractReturn), 0, `Reason: ${getReasonCode(contractReturn)}`);
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
