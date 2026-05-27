ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

ARG SCENARIO=insecure

# Simulate IronClaw installation
RUN mkdir -p /root/.ironclaw/skills

COPY testing/fixtures/ironclaw/${SCENARIO}/.env /root/.ironclaw/.env
COPY testing/fixtures/ironclaw/${SCENARIO}/config.toml /root/.ironclaw/config.toml
COPY testing/fixtures/ironclaw/${SCENARIO}/settings.json /root/.ironclaw/settings.json
COPY testing/fixtures/ironclaw/${SCENARIO}/mcp-servers.json /root/.ironclaw/mcp-servers.json

# Skills dir is only populated in the insecure fixture; secure has no skills.
COPY testing/fixtures/ironclaw/${SCENARIO}/skills/ /root/.ironclaw/skills/

# Permissions: secure scenarios use owner-only on every credential the
# adapter returns from getCredentialPaths() so CFG-003 / POL-003 pass.
RUN if [ "${SCENARIO}" != "insecure" ]; then \
      chmod 600 /root/.ironclaw/.env \
                /root/.ironclaw/config.toml \
                /root/.ironclaw/settings.json \
                /root/.ironclaw/mcp-servers.json; \
    fi

# Fake CLI binary
RUN echo '#!/bin/sh\necho "ironclaw 0.5.0"' > /usr/local/bin/ironclaw && \
    chmod +x /usr/local/bin/ironclaw

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
