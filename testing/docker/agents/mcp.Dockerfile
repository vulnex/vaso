ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

ARG SCENARIO=insecure

# Copy MCP config to a known path
COPY testing/fixtures/mcp/${SCENARIO}/claude_desktop_config.json /mcp/config.json

# For insecure scenario, copy the vulnerable server source so source-resolver can find it
# (the insecure config references /opt/mcp/admin-server.js)
COPY testing/fixtures/mcp/mcp-server-source/vulnerable-server/index.js /opt/mcp/admin-server.js

CMD ["node", "dist/cli.js", "mcp", "scan", "--path", "/mcp/config.json", "--format", "json"]
