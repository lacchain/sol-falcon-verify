const Keccak = artifacts.require("Keccak");

module.exports = function (deployer) {
  deployer.deploy(Keccak);
};
