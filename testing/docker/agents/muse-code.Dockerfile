ARG BASE_IMAGE=vaso-test-base
FROM ${BASE_IMAGE}

ARG SCENARIO=insecure

# Meta Muse Code fixture home: the launcher + .muse-version in ~/.local/bin,
# ~/.config/muse (settings.json, trust.json, auth.json, skills/) and
# ~/.local/share/muse (session transcripts, session index)
COPY testing/fixtures/muse-code/${SCENARIO}/ /root/

# insecure: Muse's own default modes under umask 002 (transcripts 0664, index
# 0644), a readable auth.json and a world-writable settings.json, with /root
# traversable so other users can actually reach them.
# secure: owner-only, as `umask 077` would leave them.
RUN if [ "${SCENARIO}" = "insecure" ]; then \
      chmod 755 /root /root/.config /root/.local /root/.local/share; \
      find /root/.config/muse /root/.local/share/muse -type d -exec chmod 775 {} +; \
      find /root/.local/share/muse -type f -exec chmod 664 {} +; \
      chmod 644 /root/.config/muse/auth.json /root/.local/share/muse/session-index.db; \
      chmod 666 /root/.config/muse/settings.json; \
      chmod 664 /root/.config/muse/trust.json; \
    else \
      find /root/.config/muse /root/.local/share/muse -type d -exec chmod 700 {} +; \
      find /root/.config/muse /root/.local/share/muse -type f -exec chmod 600 {} +; \
    fi; \
    chmod 755 /root/.local/bin/muse

CMD ["node", "dist/cli.js", "scan", "--format", "json"]
