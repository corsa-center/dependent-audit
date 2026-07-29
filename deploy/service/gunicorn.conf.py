"""Gunicorn configuration for the audit web API.

The web tier is now fast: it only validates payloads, enqueues jobs, and serves
job status/results off the shared volume. The long-running crawl happens in the
worker container, so ordinary short timeouts apply here.
"""

import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"

workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
threads = int(os.environ.get("WEB_THREADS", "4"))
worker_class = "gthread"

# Requests are quick (enqueue / poll / stream a result file). A large SPDX zip
# download is the slowest path; 120s is ample headroom.
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "120"))
graceful_timeout = 30
keepalive = 5

accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info").lower()
