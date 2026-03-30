FROM python:3.11-slim

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

RUN useradd -m -u 1000 plexus && chown -R plexus:plexus /app
USER plexus

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD \
  python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health')"

CMD ["python", "templates/run.py", "--host", "0.0.0.0", "--port", "8080"]
