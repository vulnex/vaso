import { join } from 'node:path';
import type { ScanContext } from '../../core/types.js';

/**
 * Devin's XDG data dir resolved through ctx.fs (so remote/snapshot providers
 * resolve against the scanned host): $XDG_DATA_HOME/devin, else
 * ~/.local/share/devin; %APPDATA%\devin on Windows.
 */
export function devinDataDir(ctx: ScanContext): string {
  const fs = ctx.fs;
  const home = fs.homedir();
  if (fs.platform === 'win32') {
    const appData = fs.getEnv('APPDATA');
    return join(appData?.trim() ? appData : join(home, 'AppData', 'Roaming'), 'devin');
  }
  const xdgData = fs.getEnv('XDG_DATA_HOME');
  return join(xdgData?.trim() ? xdgData : join(home, '.local', 'share'), 'devin');
}
