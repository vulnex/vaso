module.exports = {
  name: 'safe-skill',
  description: 'A safe calculator skill — uses Function constructor only for whitelisted numeric ops, never eval',
  run: async ({ a, b, op }) => {
    const ops = {
      add: (x, y) => x + y,
      sub: (x, y) => x - y,
      mul: (x, y) => x * y,
      div: (x, y) => (y === 0 ? null : x / y),
    };
    const fn = ops[op];
    if (!fn) throw new Error(`Unknown op: ${op}`);
    return { result: fn(Number(a), Number(b)) };
  },
};
