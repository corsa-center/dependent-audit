"""Gunicorn configuration for the audit web API.

The web tier is now fast: it only validates payloads, enqueues jobs, and serves
job status/results off the shared volume. The long-running crawl happens in the
worker container, so ordinary short timeouts apply here.
"""

import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"

workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
# Each open Server-Sent Events stream (GET /api/jobs/<id>/events) holds one
# thread. app.py caps streams per process at SSE_MAX_STREAMS (default 12) and
# bounds each stream's lifetime (SSE_MAX_SECONDS; browsers resume via
# Last-Event-ID), so keep threads comfortably above that cap. For many
# concurrent viewers (~50+) switch to worker_class = "gevent" instead.
threads = int(os.environ.get("WEB_THREADS", "16"))
worker_class = "gthread"

# Requests are quick (enqueue / poll / stream a result file). With gthread the
# timeout does not kill a long-lived SSE response running in a thread. A large SPDX zip
# download is the slowest path; 120s is ample headroom.
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "120"))
graceful_timeout = 30
keepalive = 5

accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info").lower()
