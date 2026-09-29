ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

ARG SCENARIO=insecure

# Simulate a Nanobot (PyPI nanobot-ai) installation: ~/.nanobot/config.json,
# the default workspace ~/.nanobot/workspace and the chat-history store
# ~/.nanobot/sessions/<workspace-id>/.
RUN mkdir -p /root/.nanobot/workspace/memory \
             /root/.nanobot/workspace/skills \
             /root/.nanobot/workspace/cron \
             /root/.nanobot/sessions

COPY testing/fixtures/nanobot/${SCENARIO}/ /root/.nanobot/

# Permissions. Secure: owner-only config/history so CFG-003 / POL-003 /
# NB-009 pass. Insecure: an exposed home (0755) with world-writable prompt,
# heartbeat and cron files (NB-006 / NB-007 / NB-010) and world-readable
# history (NB-009) — reachable by other users, so not parent-mitigated.
RUN if [ "${SCENARIO}" = "insecure" ]; then \
      chmod 755 /root && \
      chmod 644 /root/.nanobot/config.json && \
      chmod 666 /root/.nanobot/workspace/HEARTBEAT.md \
                /root/.nanobot/workspace/memory/MEMORY.md \
                /root/.nanobot/workspace/cron/jobs.json && \
      chmod -R go+rX /root/.nanobot/sessions; \
    else \
      chmod 600 /root/.nanobot/config.json && \
      chmod 700 /root/.nanobot/sessions; \
    fi

# Fake CLI binary printing nanobot's `--version` format ("🐈 nanobot v<ver>",
# emoji omitted). Insecure scenarios use a version inside the bundled
# advisory ranges so ADV-001/004 fire; secure scenarios use a later one.
RUN if [ "${SCENARIO}" = "insecure" ]; then \
      echo '#!/bin/sh\necho "nanobot v1.0.0"' > /usr/local/bin/nanobot; \
    else \
      echo '#!/bin/sh\necho "nanobot v1.4.0"' > /usr/local/bin/nanobot; \
    fi && chmod +x /usr/local/bin/nanobot

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
