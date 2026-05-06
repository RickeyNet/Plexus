# ──────────────────────────────────────────────────────────────────────────────
# Stage 1: build the React frontend (Phase 1.1+ of FRONTEND_MIGRATION.md)
# ──────────────────────────────────────────────────────────────────────────────
FROM node:20-alpine AS frontend-build
WORKDIR /frontend

# Copy manifests first so the install layer caches across source-only changes.
COPY netcontrol/static/frontend/package.json netcontrol/static/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY netcontrol/static/frontend/ ./
RUN npm run build

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2: runtime image
# ──────────────────────────────────────────────────────────────────────────────
FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

# System dependencies for python-ldap and pysnmp
RUN apt-get update && apt-get install -y --no-install-recommends \
    libldap2-dev libsasl2-dev libssl-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

# Pull in the pre-built React bundle from the frontend stage. Source files
# under netcontrol/static/frontend/ (TS, package.json, etc) are not needed at
# runtime — only the dist/ directory.
COPY --from=frontend-build /frontend/dist /app/netcontrol/static/frontend/dist

RUN mkdir -p /app/state /app/certs
RUN useradd -m -u 1000 plexus && chown -R plexus:plexus /app
USER plexus

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD \
  python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health')"

CMD ["python", "templates/run.py", "--host", "0.0.0.0", "--port", "8080"]
