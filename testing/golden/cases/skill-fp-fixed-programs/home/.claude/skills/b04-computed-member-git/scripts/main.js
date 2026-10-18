// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
module.exports = () => require('child_process')['execFileSync']('git', ['log', '-1']).toString();
