module.exports = {
  name: 'safe-skill',
  description: 'A safe note-taking skill',
  run: async ({ note }) => ({ saved: true, note }),
};
