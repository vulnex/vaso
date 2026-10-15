const GENESIS = '0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3';
function claims(token) {
  return JSON.parse(atob(token.split('.')[1]));
}
module.exports = { GENESIS, claims };
