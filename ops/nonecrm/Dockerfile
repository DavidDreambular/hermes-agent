# Native Hermes API runtime. Agent/provider code is unchanged; desktop, browser
# binaries and unrelated provider extras are not needed by this deployment.
FROM python:3.13-slim-trixie@sha256:8fb4cfa1a2616d7b8e0c2175cc6ad68f5729c34ea8488c0b360d2934b7be9024 AS builder

# Preserve the SQLite fix used by the upstream Dockerfile.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
      https://sqlite.org/2026/sqlite-autoconf-3530400.tar.gz -o /tmp/sqlite.tar.gz && \
    printf '%s  %s\n' 0e9483900e92cd5de8fd48d16bf9200145a61f7fd5be542a5ac81d8a9516eb9c /tmp/sqlite.tar.gz \
      | sha256sum -c - && \
    tar -xzf /tmp/sqlite.tar.gz -C /tmp && \
    cd /tmp/sqlite-autoconf-3530400 && \
    CFLAGS='-O2 -DSQLITE_ENABLE_FTS5 -DSQLITE_ENABLE_COLUMN_METADATA -DSQLITE_ENABLE_UNLOCK_NOTIFY -DSQLITE_ENABLE_DBSTAT_VTAB -DSQLITE_SECURE_DELETE -DSQLITE_THREADSAFE=1 -DSQLITE_MAX_VARIABLE_NUMBER=250000' \
      ./configure --prefix=/opt/sqlite-fixed --disable-static && \
    make -j2 && make install

RUN pip install --no-cache-dir uv==0.11.6
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy
WORKDIR /opt/hermes
COPY . .
# Match upstream's source-linked install so native build identity and bundled
# resources resolve under /opt/hermes. The source stays immutable for UID 10000.
RUN uv sync --frozen --no-dev --extra messaging --python /usr/local/bin/python3.13

FROM python:3.13-slim-trixie@sha256:8fb4cfa1a2616d7b8e0c2175cc6ad68f5729c34ea8488c0b360d2934b7be9024
COPY --from=builder /opt/sqlite-fixed/lib/libsqlite3.so.3.53.4 /usr/local/lib/
RUN ln -sf libsqlite3.so.3.53.4 /usr/local/lib/libsqlite3.so.0 && \
    printf '/usr/local/lib\n' > /etc/ld.so.conf.d/000-sqlite-fixed.conf && ldconfig && \
    useradd --uid 10000 --create-home --home-dir /opt/data hermes

COPY --from=builder /opt/hermes /opt/hermes
ARG SOURCE_REVISION
RUN python -c 'import re,sys; assert re.fullmatch("[0-9a-f]{40}", sys.argv[1])' "$SOURCE_REVISION" && \
    printf '%s\n' "$SOURCE_REVISION" > /opt/hermes/.hermes_build_sha && \
    printf 'docker\n' > /opt/hermes/.install_method && \
    chmod -R go-w /opt/hermes
LABEL org.opencontainers.image.source="https://github.com/DavidDreambular/hermes-agent" \
      org.opencontainers.image.revision="$SOURCE_REVISION"

ENV PATH="/opt/hermes/.venv/bin:/usr/local/bin:/usr/bin:/bin" \
    HOME=/opt/data HERMES_HOME=/opt/data HERMES_WRITE_SAFE_ROOT=/opt/data \
    HERMES_DISABLE_LAZY_INSTALLS=1 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/hermes
USER 10000:10000
EXPOSE 8642
ENTRYPOINT ["/opt/hermes/.venv/bin/hermes"]
CMD ["gateway"]
