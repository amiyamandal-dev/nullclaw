# syntax=docker/dockerfile:1

# ── Stage 1: Build ────────────────────────────────────────────
FROM alpine:3.23 AS builder

RUN apk add --no-cache zig musl-dev

WORKDIR /app
COPY build.zig build.zig.zon ./
COPY src/ src/

RUN zig build -Doptimize=ReleaseSmall

# ── Stage 2: Config Prep ─────────────────────────────────────
FROM busybox:1.37 AS config

RUN mkdir -p /nullclaw-data/.nullclaw /nullclaw-data/workspace

RUN cat > /nullclaw-data/.nullclaw/config.json << 'EOF'
{
  "api_key": "",
  "default_provider": "openrouter",
  "default_model": "anthropic/claude-sonnet-4",
  "default_temperature": 0.7,
  "gateway": {
    "port": 3000,
    "host": "::",
    "allow_public_bind": true
  }
}
EOF

# Default runtime runs as non-root (uid/gid 65534).
# Keep writable ownership for HOME/workspace in safe mode.
RUN chown -R 65534:65534 /nullclaw-data

# ── Stage 3: Runtime Base (shared) ────────────────────────────
FROM alpine:3.23 AS release-base

LABEL org.opencontainers.image.source=https://github.com/nullclaw/nullclaw

RUN apk add --no-cache ca-certificates curl tzdata

# Install pueue (task queue for background shell commands)
ARG PUEUE_VERSION=3.4.1
ARG TARGETARCH
RUN case "${TARGETARCH:-$(uname -m)}" in \
      amd64|x86_64)  ARCH=x86_64-unknown-linux-musl ;; \
      arm64|aarch64) ARCH=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported arch" && exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/Nukesor/pueue/releases/download/v${PUEUE_VERSION}/pueued-linux-${ARCH}" \
      -o /usr/local/bin/pueued && \
    curl -fsSL "https://github.com/Nukesor/pueue/releases/download/v${PUEUE_VERSION}/pueue-linux-${ARCH}" \
      -o /usr/local/bin/pueue && \
    chmod +x /usr/local/bin/pueued /usr/local/bin/pueue

COPY --from=builder /app/zig-out/bin/nullclaw /usr/local/bin/nullclaw
COPY --from=config /nullclaw-data /nullclaw-data

ENV NULLCLAW_WORKSPACE=/nullclaw-data/workspace
ENV HOME=/nullclaw-data
ENV NULLCLAW_GATEWAY_PORT=3000

WORKDIR /nullclaw-data
EXPOSE 3000
COPY <<'EOF' /usr/local/bin/entrypoint.sh
#!/bin/sh
pueued --daemonize 2>/dev/null || true
exec nullclaw "$@"
EOF
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["entrypoint.sh"]
CMD ["gateway", "--port", "3000", "--host", "::"]

# Optional autonomous mode (explicit opt-in):
#   docker build --target release-root -t nullclaw:root .
FROM release-base AS release-root
USER 0:0

# Safe default image (used when no --target is provided)
FROM release-base AS release
USER 65534:65534
