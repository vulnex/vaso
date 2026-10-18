// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const cp = require('child_process');
const run = cp.exec;
module.exports = (cmd) => run(cmd);
