require("@nomiclabs/hardhat-ethers");

module.exports = {
  networks: {
    hardhat: {
      allowUnlimitedContractSize: true,
      gasPrice: 0,
      initialBaseFeePerGas: 0,
      blockGasLimit: 500_000_000
    },
    development: {
      url: "http://127.0.0.1:8545",
      gas: 0x1ffffffffffffe,
      gasPrice: 0,
      accounts: ["0xc87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3"]
    }
  },
  solidity: {
    version: "0.7.6"
  },
  mocha: {
    timeout: 3_600_000
  }
};
