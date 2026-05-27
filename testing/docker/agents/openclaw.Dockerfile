ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

ARG SCENARIO=insecure

# Copy OpenClaw fixtures to the expected detection path
COPY testing/fixtures/openclaw/${SCENARIO}/ /root/.openclaw/

# Set permissions: insecure = world-readable (644), secure = owner-only (600)
RUN if [ "${SCENARIO}" = "insecure" ]; then \
      chmod -R 644 /root/.openclaw/; \
      find /root/.openclaw -type d -exec chmod 755 {} +; \
    else \
      chmod -R 600 /root/.openclaw/; \
      find /root/.openclaw -type d -exec chmod 700 {} +; \
    fi

# Secure scenarios additionally simulate a deployed NemoClaw sandbox so the
# four CFG-016/017/018/019 NemoClaw checks pass — they look for ~/.nemoclaw
# state on disk, not for a config flag.
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
