# ──────────────────────────────────────────────────────────────────────────────
# Stage 1: build the React frontend (netcontrol/static/frontend)
# ──────────────────────────────────────────────────────────────────────────────
FROM node:26-alpine AS frontend-build
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

# System dependencies for python-ldap and pysnmp.
# Use HTTPS mirrors: the build host blocks outbound plain HTTP (port 80),
# so the default http:// deb.debian.org URIs time out.
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' \
        /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list \
    ; apt-get update && apt-get install -y --no-install-recommends \
    libldap2-dev libsasl2-dev libssl-dev gcc gosu \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-cloud.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Cloud Visibility provider SDKs (AWS/Azure/GCP). Off by default to keep the
# base image small; build with --build-arg INSTALL_CLOUD_SDKS=true to enable
# live cloud collection.
ARG INSTALL_CLOUD_SDKS=false
RUN if [ "$INSTALL_CLOUD_SDKS" = "true" ]; then \
        pip install --no-cache-dir -r requirements-cloud.txt; \
    fi

COPY . .

# Pull in the pre-built React bundle from the frontend stage. Source files
# under netcontrol/static/frontend/ (TS, package.json, etc) are not needed at
# runtime - only the dist/ directory.
COPY --from=frontend-build /frontend/dist /app/netcontrol/static/frontend/dist

RUN mkdir -p /app/state /app/certs /app/state/software_images
RUN useradd -m -u 1000 plexus && chown -R plexus:plexus /app

COPY deploy/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Entrypoint runs as root to fix volume permissions, then drops to plexus.
USER root
ENTRYPOINT ["/docker-entrypoint.sh"]

# Release builds set these so the running container can self-identify via
# /api/version without git on PATH.  The bootstrap.sh / setup.sh flow does
# not pass them, so dev builds fall through to the netcontrol/version.py
# fallback ("1.0.0", no SHA).
ARG PLEXUS_VERSION=""
ARG PLEXUS_GIT_SHA=""
ENV PLEXUS_VERSION=${PLEXUS_VERSION}
ENV PLEXUS_GIT_SHA=${PLEXUS_GIT_SHA}

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 CMD \
  python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4)"

CMD ["python", "templates/run.py", "--host", "0.0.0.0", "--port", "8080"]
