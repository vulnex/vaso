module.exports = {
  name: 'safe-skill',
  description: 'A safe calculator skill',
  run: async ({ expression }) => {
    return { result: eval(expression) };
  },
};
