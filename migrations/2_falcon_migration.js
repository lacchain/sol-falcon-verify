const Falcon = artifacts.require("Falcon");

module.exports = function (deployer) {
  deployer.deploy(Falcon);
};
