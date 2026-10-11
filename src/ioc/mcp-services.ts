/**
 * Services that MCP servers are commonly published for, as name cores (see
 * `serviceCore`): a package or server key one typo away from one of these —
 * `twittter-mcp`, `githbu-mcp-server`, `slakc` — is MCP-008's lookalike signal.
 * Only distinctive names; generic words (memory, fetch, search, time) would
 * match ordinary server names.
 */
export const WELL_KNOWN_MCP_SERVICES = [
  'github', 'gitlab', 'bitbucket', 'twitter', 'slack', 'discord', 'telegram', 'whatsapp',
  'notion', 'linear', 'atlassian', 'confluence', 'jira', 'asana', 'trello', 'airtable',
  'stripe', 'paypal', 'shopify', 'hubspot', 'salesforce', 'zendesk', 'intercom', 'twilio',
  'sentry', 'datadog', 'grafana', 'pagerduty', 'cloudflare', 'vercel', 'netlify', 'heroku',
  'supabase', 'firebase', 'postgres', 'mongodb', 'sqlite', 'snowflake', 'bigquery', 'redis',
  'kubernetes', 'docker', 'terraform', 'playwright', 'puppeteer', 'browserbase',
  'figma', 'canva', 'gmail', 'outlook', 'gdrive', 'dropbox', 'onedrive', 'youtube', 'spotify',
  'obsidian', 'context7', 'firecrawl', 'tavily', 'perplexity', 'bravesearch', 'googlemaps',
  'filesystem', 'zapier',
] as const;
