// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
module.exports = (code) => require('vm').runInThisContext(code);
