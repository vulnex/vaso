FROM vaso-test-base

# Simulate IronClaw installation
RUN mkdir -p /root/.ironclaw/skills

COPY testing/fixtures/ironclaw/insecure/.env /root/.ironclaw/.env
COPY testing/fixtures/ironclaw/insecure/config.toml /root/.ironclaw/config.toml
COPY testing/fixtures/ironclaw/insecure/settings.json /root/.ironclaw/settings.json
COPY testing/fixtures/ironclaw/insecure/mcp-servers.json /root/.ironclaw/mcp-servers.json
COPY testing/fixtures/ironclaw/insecure/skills/ /root/.ironclaw/skills/

# Fake CLI binary
RUN echo '#!/bin/sh\necho "ironclaw 0.5.0"' > /usr/local/bin/ironclaw && \
    chmod +x /usr/local/bin/ironclaw
