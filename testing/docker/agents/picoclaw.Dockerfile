ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

ARG SCENARIO=insecure

# Copy PicoClaw fixtures to the expected detection path
COPY testing/fixtures/picoclaw/${SCENARIO}/ /root/.picoclaw/

# Set permissions
RUN if [ "${SCENARIO}" = "insecure" ]; then \
      chmod -R 644 /root/.picoclaw/; \
      find /root/.picoclaw -type d -exec chmod 755 {} +; \
    else \
      chmod -R 600 /root/.picoclaw/; \
      find /root/.picoclaw -type d -exec chmod 700 {} +; \
    fi

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
