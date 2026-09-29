ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

ARG SCENARIO=insecure
# reborn = IronClaw 1.x layout (~/.ironclaw/reborn, binary 1.4.0)
# legacy = IronClaw 0.x layout (~/.ironclaw/.env, binary 0.29.1)
ARG LAYOUT=reborn

# Stage the whole scenario, then place the layout under test.
COPY testing/fixtures/ironclaw/${SCENARIO}/ /tmp/ironclaw-fixture/

RUN set -e; \
    mkdir -p /root/.ironclaw; \
    if [ "${LAYOUT}" = "reborn" ]; then \
      cp -a /tmp/ironclaw-fixture/reborn /root/.ironclaw/reborn; \
      mkdir -p /root/.ironclaw/reborn/local-dev; \
      : > /root/.ironclaw/reborn/local-dev/reborn-local-dev.db; \
      printf '#!/bin/sh\necho "ironclaw 1.4.0"\n' > /usr/local/bin/ironclaw; \
    else \
      cp -a /tmp/ironclaw-fixture/.env /tmp/ironclaw-fixture/config.toml /tmp/ironclaw-fixture/skills /root/.ironclaw/; \
      if [ -d /tmp/ironclaw-fixture/channels ]; then cp -a /tmp/ironclaw-fixture/channels /root/.ironclaw/; fi; \
      : > /root/.ironclaw/ironclaw.db; \
      printf '#!/bin/sh\necho "ironclaw 0.29.1"\n' > /usr/local/bin/ironclaw; \
    fi; \
    chmod +x /usr/local/bin/ironclaw; \
    rm -rf /tmp/ironclaw-fixture

# Permissions: secure scenarios keep every secret owner-only (as `ironclaw
# onboard` writes them); insecure ones leave them world-readable and open
# /root so the permission findings are reachable rather than mitigated.
RUN if [ "${SCENARIO}" = "insecure" ]; then \
      chmod 755 /root /root/.ironclaw; \
      find /root/.ironclaw -type d -exec chmod 755 {} +; \
      find /root/.ironclaw -type f -exec chmod 644 {} +; \
    else \
      find /root/.ironclaw -type f \( -name webui-token -o -name '.reborn-local-dev-secrets-master-key' \
        -o -name '*.db' -o -name '.env' -o -name config.toml -o -name providers.json \) -exec chmod 600 {} +; \
    fi

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
