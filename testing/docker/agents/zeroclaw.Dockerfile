ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

ARG SCENARIO=insecure

# Simulate a ZeroClaw 0.8.x (V3 schema) installation: config dir ~/.zeroclaw
# with per-agent workspaces under agents/<alias>/workspace/.
RUN mkdir -p /root/.zeroclaw/agents /root/.zeroclaw/shared/skills /root/.zeroclaw/data

COPY testing/fixtures/zeroclaw/${SCENARIO}/config.toml /root/.zeroclaw/config.toml
COPY testing/fixtures/zeroclaw/${SCENARIO}/auth-profiles.json /root/.zeroclaw/auth-profiles.json
COPY testing/fixtures/zeroclaw/${SCENARIO}/.secret_key /root/.zeroclaw/.secret_key
COPY testing/fixtures/zeroclaw/${SCENARIO}/agents/ /root/.zeroclaw/agents/

# Permissions: insecure leaves credentials world-readable (so ZC-013 / CFG-003
# / POL-003 fire); secure tightens every credential to owner-only.
RUN if [ "${SCENARIO}" = "insecure" ]; then \
      chmod 644 /root/.zeroclaw/.secret_key \
                /root/.zeroclaw/config.toml \
                /root/.zeroclaw/auth-profiles.json; \
    else \
      chmod 600 /root/.zeroclaw/.secret_key \
                /root/.zeroclaw/config.toml \
                /root/.zeroclaw/auth-profiles.json; \
    fi

# Fake CLI binary (real output: "zeroclaw 0.8.5")
RUN echo '#!/bin/sh\necho "zeroclaw 0.8.5"' > /usr/local/bin/zeroclaw && \
    chmod +x /usr/local/bin/zeroclaw

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
