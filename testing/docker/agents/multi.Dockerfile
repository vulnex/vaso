ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

ARG SCENARIO=insecure

# Copy all three agent fixtures to their expected paths

# OpenClaw
COPY testing/fixtures/openclaw/${SCENARIO}/ /root/.openclaw/

# NanoClaw
COPY testing/fixtures/nanoclaw/${SCENARIO}/ /root/.config/nanoclaw/
COPY testing/fixtures/nanoclaw/${SCENARIO}/.nanoclaw.env /root/.nanoclaw.env

# PicoClaw
COPY testing/fixtures/picoclaw/${SCENARIO}/ /root/.picoclaw/

# Set permissions
RUN if [ "${SCENARIO}" = "insecure" ]; then \
      chmod -R 644 /root/.openclaw/ /root/.config/nanoclaw/ /root/.picoclaw/; \
      find /root/.openclaw /root/.config/nanoclaw /root/.picoclaw -type d -exec chmod 755 {} +; \
      chmod 644 /root/.nanoclaw.env; \
    else \
      chmod -R 600 /root/.openclaw/ /root/.config/nanoclaw/ /root/.picoclaw/; \
      find /root/.openclaw /root/.config/nanoclaw /root/.picoclaw -type d -exec chmod 700 {} +; \
      chmod 600 /root/.nanoclaw.env; \
    fi

# Secure scenarios additionally simulate a deployed NemoClaw sandbox so the
# CFG-016/017/018/019 checks pass for the OpenClaw co-tenant.
RUN if [ "${SCENARIO}" != "insecure" ]; then \
      mkdir -p /root/.nemoclaw/state && \
      printf '%s\n' '{' \
        '  "lastAction": "deploy",' \
        '  "lastRunId": "run-001",' \
        '  "sandboxName": "openclaw-default",' \
        '  "blueprintVersion": "1.0.0",' \
        '  "migrationSnapshot": "/root/.nemoclaw/snapshots/run-001"' \
        '}' > /root/.nemoclaw/state/nemoclaw.json; \
    fi

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
