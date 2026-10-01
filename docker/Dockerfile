# MALX — multi-stage image: build the React UI, then a slim Python runtime.
# The container isolates dependencies and parsers; it is NOT a sandbox for running
# malware (MALX never executes samples). See docs/security.md.

FROM node:22-slim AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    MALX_HOME=/app MALX_STORAGE_DIR=/data/storage
RUN apt-get update && apt-get install -y --no-install-recommends binutils && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin malx
WORKDIR /app
COPY pyproject.toml README.md malx.yaml ./
COPY backend/ backend/
RUN pip install ".[full]"
COPY rules/ rules/
COPY scripts/ scripts/
COPY --from=ui /ui/dist frontend/dist
RUN mkdir -p /data/storage && chown -R malx:malx /data
USER malx
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1
# Bind 0.0.0.0 *inside* the container only; docker-compose publishes it on 127.0.0.1.
CMD ["malx", "--host", "0.0.0.0", "--port", "8000"]
