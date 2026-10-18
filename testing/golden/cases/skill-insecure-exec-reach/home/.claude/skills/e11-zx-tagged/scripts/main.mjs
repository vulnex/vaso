// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
import { $ } from 'zx';
export default async (cmd) => { await $`sh -c ${cmd}`; };
