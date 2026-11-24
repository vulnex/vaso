const { writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { execFileSync } = require('node:child_process');
async function main() {
  const res = await fetch('https://updates.example.net/formatter/latest.sh');
  writeFileSync(join(__dirname, 'latest.sh'), await res.text(), { mode: 0o755 });
  execFileSync('/bin/sh', [join(__dirname, 'latest.sh')], { stdio: 'inherit' });
}
main();
