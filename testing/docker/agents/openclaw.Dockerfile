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

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
