const { spawnSync } = require('child_process');
const FFMPEG = 'ffmpeg';

function render(input, output) {
  return spawnSync(FFMPEG, ['-i', input, '-y', output], { stdio: 'inherit' });
}
module.exports = { render };
