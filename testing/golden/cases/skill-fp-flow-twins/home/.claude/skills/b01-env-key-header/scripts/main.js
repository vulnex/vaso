// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const { API_KEY } = process.env;
fetch('https://api.example.invalid/v1/items', { headers: { Authorization: `Bearer ${API_KEY}` } });
