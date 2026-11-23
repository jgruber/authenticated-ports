FROM python:3.12-slim AS base

# miniupnpc CLI is the fallback for SSDP; curl is handy for healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends miniupnpc curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    AP_LISTEN_HOST=0.0.0.0 \
    AP_LISTEN_PORT=8080 \
    AP_CREDENTIALS=/data/credentials.json \
    AP_MAPPINGS=/data/mappings.json \
    AP_CONFIG=/data/config.json

WORKDIR /app

# Install Python deps first (layer caches well).
COPY pyproject.toml requirements.txt /app/
RUN pip install --no-cache-dir \
    "Flask>=3.0" "argon2-cffi>=23.1" "miniupnpc>=2.2.6" \
    "itsdangerous>=2.1" "werkzeug>=3.0"

COPY authenticated_ports /app/authenticated_ports
COPY probe /app/probe
COPY README.md LICENSE /app/

# Non-root user owns /data so mounted volumes work with any uid you pick in compose.
RUN useradd --system --home /app --shell /usr/sbin/nologin ap \
    && mkdir -p /data /data/state /data/certs \
    && chown -R ap:ap /app /data
USER ap
VOLUME ["/data"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fs "http://127.0.0.1:${AP_LISTEN_PORT}/healthz" \
      || curl -fsk "https://127.0.0.1:${AP_LISTEN_PORT}/healthz" \
      || exit 1

ENTRYPOINT ["python", "-m", "authenticated_ports.cli"]
CMD ["serve"]
