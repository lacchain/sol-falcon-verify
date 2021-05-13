const HDWalletProvider = require('@truffle/hdwallet-provider');

module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "*",
      gas: "0x1ffffffffffffe",
      gasPrice: 0,
      provider: () => new HDWalletProvider('0xc87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3', 'http://localhost:8545')
    }
  },

  compilers: {
    solc: {
      version: "0.7.0"
    }
  }
};
