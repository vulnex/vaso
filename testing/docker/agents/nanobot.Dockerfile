FROM vaso-test-base

# Simulate Nanobot installation
RUN mkdir -p /root/.nanobot/workspace/{memory,skills,sessions}

COPY testing/fixtures/nanobot/insecure/config.json /root/.nanobot/config.json
COPY testing/fixtures/nanobot/insecure/workspace/ /root/.nanobot/workspace/

# Fake CLI binary
RUN echo '#!/bin/sh\necho "nanobot 1.0.0"' > /usr/local/bin/nanobot && \
    chmod +x /usr/local/bin/nanobot
