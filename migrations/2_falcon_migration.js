const Falcon = artifacts.require("Falcon");
const LibUtils = artifacts.require("LibUtils");

module.exports = function(deployer) {
  deployer.deploy(LibUtils)
    .then(() => {
      return deployer.link(LibUtils, Falcon);
    })
    .then(() => {
      return deployer.deploy(Falcon);
    });
};
