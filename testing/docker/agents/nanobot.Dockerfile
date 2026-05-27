ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

ARG SCENARIO=insecure

# Simulate Nanobot installation
RUN mkdir -p /root/.nanobot/workspace/memory \
             /root/.nanobot/workspace/skills \
             /root/.nanobot/workspace/sessions

COPY testing/fixtures/nanobot/${SCENARIO}/config.json /root/.nanobot/config.json
COPY testing/fixtures/nanobot/${SCENARIO}/workspace/ /root/.nanobot/workspace/

# Permissions: secure scenario tightens credential files to owner-only so
# CFG-003 / POL-003 pass.
RUN if [ "${SCENARIO}" != "insecure" ]; then \
      chmod 600 /root/.nanobot/config.json; \
    fi

# Fake CLI binary. Insecure scenarios use a known-vulnerable version (1.0.0)
# so ADV-001/004 fires against bundled CVE-2026-40040/40041; secure scenarios
# use a post-fix version (1.4.0+) so the same checks pass.
RUN if [ "${SCENARIO}" = "insecure" ]; then \
      echo '#!/bin/sh\necho "nanobot 1.0.0"' > /usr/local/bin/nanobot; \
    else \
      echo '#!/bin/sh\necho "nanobot 1.4.0"' > /usr/local/bin/nanobot; \
    fi && chmod +x /usr/local/bin/nanobot

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
