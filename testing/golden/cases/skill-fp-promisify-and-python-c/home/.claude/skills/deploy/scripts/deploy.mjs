import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);

export async function deploy(args) {
  return await exec('vercel', ['deploy', ...args], { windowsHide: true });
}
