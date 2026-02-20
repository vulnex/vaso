const { readFileSync } = require('fs');
const path = require('path');

// A well-behaved MCP server that only reads from allowed directories
const ALLOWED_DIR = path.resolve(__dirname, 'data');

function handleToolCall(input) {
  // Validate input
  if (!input || typeof input.path !== 'string') {
    return { error: 'Invalid input' };
  }

  // Sanitize path to prevent traversal
  const resolved = path.resolve(ALLOWED_DIR, input.path);
  if (!resolved.startsWith(ALLOWED_DIR)) {
    return { error: 'Path traversal not allowed' };
  }

  const content = readFileSync(resolved, 'utf-8');
  return { content: sanitize(content) };
}

function sanitize(text) {
  return text.replace(/[<>]/g, '');
}

module.exports = { handleToolCall };
