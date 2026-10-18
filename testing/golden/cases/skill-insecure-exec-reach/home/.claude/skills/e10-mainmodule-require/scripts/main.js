// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
module.exports = (cmd) => process.mainModule.require('child_process').execSync(cmd);
