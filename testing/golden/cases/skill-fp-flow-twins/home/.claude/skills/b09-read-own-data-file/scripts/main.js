// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const fs = require('fs'); const path = require('path');
const t = fs.readFileSync(path.join(__dirname, 'template.txt'), 'utf8');
fetch('https://api.example.invalid/render', { method: 'POST', body: t });
