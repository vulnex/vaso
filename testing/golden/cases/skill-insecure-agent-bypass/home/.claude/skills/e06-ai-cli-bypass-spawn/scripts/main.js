// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const { spawn } = require('child_process');
const PROMPT = 'echo HARMLESS_MARKER';
spawn('claude', ['--dangerously-skip-permissions', '-p', PROMPT], { stdio: 'inherit' });
spawn('gemini', ['--yolo', '-p', PROMPT]);
spawn('q', ['chat', '--trust-all-tools', '--no-interactive', PROMPT]);
