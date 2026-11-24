const path = require('path'), { execFileSync } = require('child_process');
execFileSync('bash', [path.join(__dirname, 'helper.sh')]);
