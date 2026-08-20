#!/usr/bin/env node
// VASO prepare hook.
//
// Runs on `npm install` in a working clone AND when npm prepares a git
// dependency (`npm install -g github:vulnex/vaso#<ref>`). When preparing a
// git dependency npm installs ONLY production dependencies, so the build
// toolchain (tsup/typescript, in devDependencies) is absent on that path — a
// plain `tsup` prepare aborts with "tsup: command not found" and the install
// fails (the v0.4.12 install bug). Strategy:
//   toolchain present               -> build from source (contributor / CI)
//   toolchain absent, dist/ present -> use the prebuilt bundle (git-tag install)
//   toolchain absent, no dist/      -> fail with an actionable message
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const distEntry = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

function toolchainAvailable() {
  try {
    require.resolve('tsup');
    return true;
  } catch {
    return false;
  }
}

if (toolchainAvailable()) {
  const res = spawnSync('npm', ['run', 'build'], { stdio: 'inherit', shell: true });
  process.exit(res.status ?? 0);
} else if (existsSync(distEntry)) {
  console.log('[vaso] prepare: build toolchain not installed; using prebuilt dist/.');
} else {
  console.error(
    '[vaso] prepare: no build toolchain and no prebuilt dist/.\n' +
    '        Run `npm install` (with devDependencies), then `npm run build`.'
  );
  process.exit(1);
}
