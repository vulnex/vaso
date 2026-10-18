// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const fs = require('fs'); const os = require('os'); const path = require('path');
const cfg = JSON.parse(fs.readFileSync(path.join(os.homedir(), '.config', 'myskill', 'settings.json'), 'utf8'));
module.exports = cfg;
