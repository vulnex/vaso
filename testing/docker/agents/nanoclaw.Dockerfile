ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

ARG SCENARIO=insecure

# NanoClaw v2 layout: a git checkout (package.json name "nanoclaw", .env,
# data/, container/skills/, src/channels/index.ts) plus the host config dir
# ~/.config/nanoclaw holding the mount allowlist.
COPY testing/fixtures/nanoclaw/${SCENARIO}/checkout/ /root/nanoclaw/
COPY testing/fixtures/nanoclaw/${SCENARIO}/config/ /root/.config/nanoclaw/

# Insecure: world-writable checkout/state/skills/allowlist and a world-readable
# .env; /root opened to 755 so the exposure is reachable (not parent-mitigated).
RUN if [ "${SCENARIO}" = "insecure" ]; then \
      chmod 755 /root /root/.config; \
      chmod 777 /root/nanoclaw /root/nanoclaw/data /root/nanoclaw/container/skills /root/.config/nanoclaw; \
      chmod 666 /root/.config/nanoclaw/mount-allowlist.json; \
      chmod 644 /root/nanoclaw/.env; \
    else \
      chmod 755 /root/nanoclaw /root/nanoclaw/container/skills; \
      chmod 700 /root/nanoclaw/data /root/.config/nanoclaw; \
      chmod 600 /root/.config/nanoclaw/mount-allowlist.json /root/nanoclaw/.env; \
    fi

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
