# Minimal non-root container for omada-mcp (zero runtime dependencies, Web API v2)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    OMADA_READ_ONLY=true

WORKDIR /app

RUN groupadd --system --gid 10001 omada \
    && useradd --system --uid 10001 --gid omada --no-create-home omada \
    && mkdir -p /data/snapshots \
    && chown -R omada:omada /app /data

COPY pyproject.toml README.md /app/
COPY src /app/src

ENV OMADA_SNAPSHOT_DIR=/data/snapshots

USER omada

# Default mode runs the read-only MCP stdio bridge.
# Override arguments for operational modes, e.g.:
#   docker run --rm --env-file .env omada-mcp --watch --interval 30
#   docker run --rm -p 9108:9108 --env-file .env omada-mcp --export-metrics --metrics-port 9108 --metrics-host 0.0.0.0
ENTRYPOINT ["python", "-m", "omada_mcp"]
