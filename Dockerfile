# syntax=docker/dockerfile:1
#
# Magi team server as a container. Multi-stage: the first stage bundles the app into a
# single self-contained file (public/ and Express are compiled in; SQLite is built into
# Node), the second ships only Node + openssl + that bundle.
#
#   docker compose up -d --build          (see docker-compose.yml)
# or
#   docker build -t magi-server .
#   docker run -d -p 8443:8443 -v magi-data:/data -e MAGI_PASS=... magi-server

# ---- build: bundle the server + CLI ----
FROM node:26-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN node build/build.mjs

# ---- runtime: Node + openssl + the bundle, nothing else ----
FROM node:26-slim AS runtime
LABEL org.opencontainers.image.title="Magi team server" \
      org.opencontainers.image.description="The pentester's familiar — shared engagement server" \
      org.opencontainers.image.source="https://github.com/MammadovIzzat/Magi"
# openssl: the server shells out to it once to mint its durable certificate.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/dist/magi.cjs     ./magi.cjs
COPY --from=build /app/dist/magi-cli.cjs ./magi-cli.cjs
# /data may be a HOST bind-mount that Docker created as root — so the container starts as
# root, makes /data writable by the unprivileged `node` user, then drops to it via setpriv
# (util-linux, already in the base image). The app itself never runs as root. The `magi`
# CLI wrapper drops the same way so `docker compose exec magi magi enroll-code` also works.
RUN printf '#!/bin/sh\nif [ "$(id -u)" = 0 ]; then chown -R node:node /data 2>/dev/null || true; exec setpriv --reuid=node --regid=node --init-groups "$@"; fi\nexec "$@"\n' > /usr/local/bin/magi-entry \
    && printf '#!/bin/sh\nif [ "$(id -u)" = 0 ]; then exec setpriv --reuid=node --regid=node --init-groups node /app/magi-cli.cjs "$@"; fi\nexec node /app/magi-cli.cjs "$@"\n' > /usr/local/bin/magi \
    && chmod +x /usr/local/bin/magi-entry /usr/local/bin/magi \
    && mkdir -p /data && chown -R node:node /data /app
# Durable data — the database, the certificate and the server identity all live here, so it
# MUST be a persistent volume. Restarting then never re-runs setup and never re-mints the cert.
ENV MAGI_SERVER=1 \
    MAGI_HOST=0.0.0.0 \
    MAGI_PORT=8443 \
    MAGI_DATA_DIR=/data
EXPOSE 8443
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/magi-entry"]
CMD ["node", "magi.cjs"]
