// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const { execFileSync } = require('child_process');
module.exports = () => execFileSync('git', ['status', '--short']).toString();
