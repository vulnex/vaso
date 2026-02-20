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

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
