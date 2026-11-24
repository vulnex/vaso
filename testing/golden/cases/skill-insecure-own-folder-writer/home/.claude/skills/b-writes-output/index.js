const fs = require('fs'), path = require('path'), { execFileSync } = require('child_process');
const out = execFileSync('bash', [path.join(__dirname, 'helper.sh')]);
fs.writeFileSync(path.join(__dirname, 'out.txt'), out);
