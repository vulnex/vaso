// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const dns = require('dns');
dns.lookup('api.example.invalid', (e, addr) => console.log(Buffer.byteLength(String(addr))));
