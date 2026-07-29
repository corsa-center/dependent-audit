# One image serves two roles (web API + worker); compose picks via `command`.
# Build context is the repo root (see docker-compose.yml) so we can copy the
# crawler in alongside the service code.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first for layer caching.
COPY deploy/service/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# The crawler (single-file) plus the service code.
COPY audit_dependents.py /app/audit_dependents.py
COPY deploy/service/auditlib.py /app/auditlib.py
COPY deploy/service/app.py /app/app.py
COPY deploy/service/worker.py /app/worker.py
COPY deploy/service/gunicorn.conf.py /app/gunicorn.conf.py

# Unprivileged user + a shared job dir. Creating /data here means a fresh named
# volume mounted at /data inherits this ownership on first init, so both the
# web and worker containers (same uid) can read/write jobs.
RUN useradd --create-home --uid 10001 audit \
    && mkdir -p /data/jobs \
    && chown -R audit:audit /data
USER audit

ENV AUDIT_SCRIPT=/app/audit_dependents.py \
    JOBS_DIR=/data/jobs \
    PORT=8000

EXPOSE 8000

# Default role is the web API; the worker service overrides `command`.
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
