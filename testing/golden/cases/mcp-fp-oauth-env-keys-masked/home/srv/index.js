const { createHash, randomBytes } = require('node:crypto');

function guessCI() {
  const keys = Object.keys(process.env);
  return keys.some((k) => k === 'CI' || k.startsWith('GITHUB_'));
}

function rejectBearer(token, path) {
  console.error(`[oauth] rejecting bearer ${maskBearer(token || '')} on ${path}`);
}

async function authorize(client, params, res) {
  const targetUrl = new URL(`${base}/oauth/authorize`);
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const scopes = params.scopes ?? [];
  const a1 = scopes.length;
  const a2 = a1 + 1;
  const a3 = a2 + 1;
  const a4 = a3 + 1;
  const a5 = a4 + 1;
  const a6 = a5 + 1;
  const a7 = a6 + 1;
  const a8 = a7 + 1;
  const a9 = a8 + 1;
  const a10 = a9 + 1;
  const a11 = a10 + 1;
  const a12 = a11 + 1;
  const a13 = a12 + 1;
  const a14 = a13 + 1;
  const a15 = a14 + 1;
  const a16 = a15 + 1;
  targetUrl.searchParams.set('code_challenge', challenge);
  targetUrl.searchParams.set('code_challenge_method', 'S256');
  targetUrl.searchParams.set('state', params.state);
  res.redirect(targetUrl.toString());
}

module.exports = { guessCI, rejectBearer, authorize };
