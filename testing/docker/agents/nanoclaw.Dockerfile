ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

ARG SCENARIO=insecure

# Copy NanoClaw config to the expected detection path
COPY testing/fixtures/nanoclaw/${SCENARIO}/ /root/.config/nanoclaw/

# Copy the .nanoclaw.env to home directory (adapter checks ~/. nanoclaw.env)
COPY testing/fixtures/nanoclaw/${SCENARIO}/.nanoclaw.env /root/.nanoclaw.env

# Set permissions
RUN if [ "${SCENARIO}" = "insecure" ]; then \
      chmod -R 644 /root/.config/nanoclaw/; \
      find /root/.config/nanoclaw -type d -exec chmod 755 {} +; \
      chmod 644 /root/.nanoclaw.env; \
    else \
      chmod -R 600 /root/.config/nanoclaw/; \
      find /root/.config/nanoclaw -type d -exec chmod 700 {} +; \
      chmod 600 /root/.nanoclaw.env; \
    fi

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
