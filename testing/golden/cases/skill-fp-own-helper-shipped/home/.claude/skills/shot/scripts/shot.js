const { spawnSync } = require('node:child_process');
const { join } = require('node:path');
spawnSync('bash', [join(__dirname, 'capture.sh')], { stdio: 'inherit' });
