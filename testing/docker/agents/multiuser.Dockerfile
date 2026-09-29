ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

# A multi-user host: alice runs PicoClaw + Nanobot, bob runs ZeroClaw + Nanobot,
# root runs nothing. `vaso scan --all-users` (as root) must attribute each
# install to its user and report each once.
RUN useradd -m -s /bin/bash alice && useradd -m -s /bin/bash bob

COPY testing/fixtures/picoclaw/insecure/ /home/alice/.picoclaw/
COPY testing/fixtures/nanobot/insecure/ /home/alice/.nanobot/
COPY testing/fixtures/zeroclaw/secure/ /home/bob/.zeroclaw/
COPY testing/fixtures/nanobot/insecure/ /home/bob/.nanobot/

# alice's home is private (0700), bob's is traversable (0755) with a
# world-readable nanobot config — reachable by other users.
RUN chown -R alice:alice /home/alice && chown -R bob:bob /home/bob \
 && chmod 700 /home/alice && chmod 755 /home/bob \
 && chmod 644 /home/alice/.nanobot/config.json /home/bob/.nanobot/config.json

CMD ["node", "dist/cli.js", "scan", "--format", "json", "--all-users"]
