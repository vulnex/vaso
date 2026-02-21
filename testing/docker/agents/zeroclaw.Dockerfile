FROM vaso-test-base

# Simulate ZeroClaw installation
RUN mkdir -p /root/.zeroclaw/workspace/skills

COPY testing/fixtures/zeroclaw/insecure/config.toml /root/.zeroclaw/config.toml
COPY testing/fixtures/zeroclaw/insecure/auth-profiles.json /root/.zeroclaw/auth-profiles.json
COPY testing/fixtures/zeroclaw/insecure/.secret_key /root/.zeroclaw/.secret_key

# Intentionally set bad permissions on .secret_key
RUN chmod 644 /root/.zeroclaw/.secret_key

COPY testing/fixtures/zeroclaw/insecure/workspace/ /root/.zeroclaw/workspace/

# Fake CLI binary
RUN echo '#!/bin/sh\necho "zeroclaw 0.3.0"' > /usr/local/bin/zeroclaw && \
    chmod +x /usr/local/bin/zeroclaw
