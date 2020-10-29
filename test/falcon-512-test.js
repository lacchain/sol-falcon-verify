const Falcon = artifacts.require("Falcon");

contract("Falcon", accounts => {
  let falcon;

  before(async () => {
    falcon = await Falcon.deployed();
  });

  it("has EIP-152 enabled", async () => {
    // from https://eips.ethereum.org/EIPS/eip-152#test-vector-4
    let ret = await web3.eth.call({
      from: accounts[0],
      to: '0x0000000000000000000000000000000000000009',
      data: '0x0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001'
    });
    assert.equal(ret, '0x08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b')
  });

  describe("Public key", async () => {
    it("cannot be empty", async () => {
      let pubKey = Buffer.alloc(0);
      let ret = await falcon.verify.call(Buffer.alloc(42), 0, pubKey, Buffer.alloc(0));
      assert.equal(ret, -3, 'Error return doesn\'t match Falcon.FALCON_ERR_FORMAT');
    });

    it("has to begin with 0x0", async() => {
      let pubKey = Buffer.from('B0', 'hex');
      let ret = await falcon.verify.call(Buffer.alloc(42), 0, pubKey, Buffer.alloc(0));
      assert.equal(ret, -3, 'Error return doesn\'t match Falcon.FALCON_ERR_FORMAT');
    });

    it("has to have second nibble between 1 and 10", async() => {
      let pubKey = Buffer.from('0B', 'hex');
      let ret = await falcon.verify.call(Buffer.alloc(42), 0, pubKey, Buffer.alloc(0));
      assert.equal(ret, -3, 'Error return doesn\'t match Falcon.FALCON_ERR_FORMAT');
    });
  })

  describe("Signature", async() => {
    it("has to be longer than 41 bytes", async () => {
      let signature = Buffer.alloc(0);
      let ret = await falcon.verify.call(signature, 0, Buffer.alloc(1), Buffer.alloc(0));
      assert.equal(ret, -3, 'Error return doesn\'t match Falcon.FALCON_ERR_FORMAT');
    });

    it("has to match second nibble with public key", async() => {
      let signature = Buffer.alloc(42);
      signature.write('0A', 0, 1, 'hex');
      let pubKey = Buffer.from('09', 'hex');
      let ret = await falcon.verify.call(signature, 0, pubKey, Buffer.alloc(0));
      assert.equal(ret, -4, 'Error return doesn\'t match Falcon.FALCON_ERR_BADSIG');
    });
  });

  describe("Signature type", async() => {
    it("has to be 0, 1, 2 or 3", async() => {
      let signature = Buffer.alloc(42);
      signature.write('0A', 0, 1, 'hex');
      let pubKey = Buffer.from('0A', 'hex');
      let signatureType = 4;
      let ret = await falcon.verify.call(signature, signatureType, pubKey, Buffer.alloc(0));
      assert.equal(ret, -5, 'Error return doesn\'t match Falcon.FALCON_ERR_BADARG');
    });

    it("INFERRED: has to have the first nibble of the signature equal to 3 or 5", async() => {
      let signature = Buffer.alloc(42);
      signature.write('0A', 0, 1, 'hex');
      let pubKey = Buffer.from('0A', 'hex');
      let signatureType = 0;
      let ret = await falcon.verify.call(signature, signatureType, pubKey, Buffer.alloc(0));
      assert.equal(ret, -4, 'Error return doesn\'t match Falcon.FALCON_ERR_BADSIG');
    })

    it("INFERRED: has to have proper signature length in the public key", async() => {
      let signature = Buffer.alloc(42);
      signature.write('31', 0, 1, 'hex');
      let pubKey = Buffer.from('01', 'hex'); // 1 means signature size of 44 bytes
      let signatureType = 0;
      let ret = await falcon.verify.call(signature, signatureType, pubKey, Buffer.alloc(0));
      assert.equal(ret, -3, 'Error return doesn\'t match Falcon.FALCON_ERR_FORMAT');
    });

    it("COMPRESSED: has to have first nibble of signature equals 3", async() => {
      let signature = Buffer.alloc(44);
      signature.write('21', 0, 1, 'hex');
      let pubKey = Buffer.from('01', 'hex');
      let signatureType = 1;
      let ret = await falcon.verify.call(signature, signatureType, pubKey, Buffer.alloc(0));
      assert.equal(ret, -3, 'Error return doesn\'t match Falcon.FALCON_ERR_FORMAT');
    });

    it("PADDED: has to have first nibble of signature equals 3", async() => {
      let signature = Buffer.alloc(44);
      signature.write('21', 0, 1, 'hex');
      let pubKey = Buffer.from('01', 'hex');
      let signatureType = 2;
      let ret = await falcon.verify.call(signature, signatureType, pubKey, Buffer.alloc(0));
      assert.equal(ret, -3, 'Error return doesn\'t match Falcon.FALCON_ERR_FORMAT');
    });

    it("PADDED: has to have proper signature length in the public key", async() => {
      let signature = Buffer.alloc(42);
      signature.write('31', 0, 1, 'hex');
      let pubKey = Buffer.from('01', 'hex'); // 1 means signature size of 44 bytes
      let signatureType = 2;
      let ret = await falcon.verify.call(signature, signatureType, pubKey, Buffer.alloc(0));
      assert.equal(ret, -3, 'Error return doesn\'t match Falcon.FALCON_ERR_FORMAT');
    });

    it("CONSTANT-TIME: has to have first nibble of signature equals 5", async() => {
      let signature = Buffer.alloc(44);
      signature.write('41', 0, 1, 'hex');
      let pubKey = Buffer.from('01', 'hex'); // 1 means signature size of 44 bytes
      let signatureType = 3;
      let ret = await falcon.verify.call(signature, signatureType, pubKey, Buffer.alloc(0));
      assert.equal(ret, -3, 'Error return doesn\'t match Falcon.FALCON_ERR_FORMAT');
    });

    it("CONSTANT-TIME: has to have proper signature length in the public key", async() => {
      let signature = Buffer.alloc(42);
      signature.write('51', 0, 1, 'hex');
      let pubKey = Buffer.from('01', 'hex'); // 1 means signature size of 44 bytes
      let signatureType = 3;
      let ret = await falcon.verify.call(signature, signatureType, pubKey, Buffer.alloc(0));
      assert.equal(ret, -3, 'Error return doesn\'t match Falcon.FALCON_ERR_FORMAT');
    });
  });
});
