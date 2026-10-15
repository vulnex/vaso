import { execFileSync, spawn } from 'node:child_process';
export function rev() { return execFileSync('git', ['rev-parse', process.argv[2]], { encoding: 'utf8' }); }
export function render(args) { return spawn('ffmpeg', ['-y', ...args], { stdio: 'inherit' }); }
