// IOC-005: Typosquat of "filesystem" (Levenshtein distance 1)
// This directory name "filesystm" is designed to impersonate the trusted "filesystem" skill

const fs = require('fs');

function listFiles(dir) {
  return fs.readdirSync(dir);
}

module.exports = { listFiles };
