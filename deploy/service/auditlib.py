"""Shared building blocks for the async audit service.

Both the web API (``app.py``) and the worker (``worker.py``) import this module.
It owns two things:

1. The payload -> CLI-argv mapping (the request schema, mirroring the
   ``audit_dependents.py`` flags one-for-one).
2. A small filesystem-backed :class:`JobStore` used as a shared queue + result
   store, so the web tier and the worker tier communicate purely through a
   shared volume — no broker/DB dependency.

Each job lives in ``<jobs_dir>/<id>/``:

    payload.json            the (normalized) request
    meta.json               {id, status, timestamps, error, returncode}
    queued                  sentinel; atomically renamed to `claimed` on pickup
    claimed                 sentinel present once a worker owns the job
    dependency_graph.json   the crawler output (on success)
    spdx_snippets/          per-edge SPDX snippets (on success)
    stderr.log              tail of the crawler's stderr (on failure)

Status flows: queued -> running -> (succeeded | failed | timeout).
"""

import json
import os
import sys
import time
import uuid

# ---------------------------------------------------------------------------
# Payload -> CLI mapping. Payload key == flag name minus "--", underscored.
# ---------------------------------------------------------------------------

STRING_OPTS = {
    "repo": "--repo",
    "name": "--name",
    "ecosystem": "--ecosystem",
    "email": "--email",
    "academic_keyword": "--academic-keyword",
    "sg_count": "--sg-count",
    "idf_cache": "--idf-cache",
    "declared_sources": "--declared-sources",
    "custom_string": "--custom-string",
    "custom_file": "--custom-file",
}
INT_OPTS = {
    "depth": "--depth",
    "idf_cap": "--idf-cap",
}
FLOAT_OPTS = {
    "sg_delay": "--sg-delay",
}
FLAG_OPTS = {
    "verbose": "--verbose",
    "forks": "--forks",
    "include_archived": "--include-archived",
    "include_vendored": "--include-vendored",
    "no_idf": "--no-idf",
    "no_defaults": "--no-defaults",
}
# Secrets: forwarded via the subprocess env (never the command line, which would
# leak into the process table). The CLI reads these env vars as flag defaults.
TOKEN_ENV = {
    "sg_token": "SG_TOKEN",
    "gh_token": "GH_TOKEN",
}

REQUIRED = ("repo", "name")

# Path to the crawler; overridable so the image layout can change freely.
AUDIT_SCRIPT = os.environ.get(
    "AUDIT_SCRIPT", os.path.join(os.path.dirname(__file__), "audit_dependents.py")
)

# Service-only payload keys that are not passed through to the CLI.
SERVICE_KEYS = {"out", "include_spdx"}

KNOWN_KEYS = (
    set(STRING_OPTS)
    | set(INT_OPTS)
    | set(FLOAT_OPTS)
    | set(FLAG_OPTS)
    | set(TOKEN_ENV)
    | SERVICE_KEYS
)

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_TIMEOUT = "timeout"
TERMINAL_STATUSES = {STATUS_SUCCEEDED, STATUS_FAILED, STATUS_TIMEOUT}


def normalize(payload):
    """Accept hyphenated or underscored keys; return an underscored copy."""
    return {str(k).replace("-", "_"): v for k, v in (payload or {}).items()}


def truthy(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def validate(payload):
    """Raise ValueError if the (normalized) payload is malformed.

    Runs the same checks and type coercions as :func:`build_argv` so a bad
    request is rejected at submit time with a 400 rather than failing later in
    the worker.
    """
    build_argv(payload, out_path="/dev/null")


def build_argv(payload, out_path):
    """Translate a normalized payload into an argv list for the crawler.

    Raises ValueError on malformed input.
    """
    argv = [sys.executable, AUDIT_SCRIPT]

    missing = [k for k in REQUIRED if not payload.get(k)]
    if missing:
        raise ValueError(f"missing required field(s): {', '.join(missing)}")

    unknown = set(payload) - KNOWN_KEYS
    if unknown:
        raise ValueError(f"unknown field(s): {', '.join(sorted(unknown))}")

    for key, flag in STRING_OPTS.items():
        if payload.get(key) not in (None, ""):
            argv += [flag, str(payload[key])]

    for key, flag in INT_OPTS.items():
        if payload.get(key) is not None:
            try:
                argv += [flag, str(int(payload[key]))]
            except (TypeError, ValueError):
                raise ValueError(f"'{key}' must be an integer")

    for key, flag in FLOAT_OPTS.items():
        if payload.get(key) is not None:
            try:
                argv += [flag, str(float(payload[key]))]
            except (TypeError, ValueError):
                raise ValueError(f"'{key}' must be a number")

    for key, flag in FLAG_OPTS.items():
        if key in payload and truthy(payload[key]):
            argv.append(flag)

    # The service owns the output location; any client "out" is ignored.
    argv += ["--out", out_path]
    return argv


def build_env(payload, base_env=None):
    env = dict(base_env if base_env is not None else os.environ)
    for key, env_name in TOKEN_ENV.items():
        if payload.get(key):
            env[env_name] = str(payload[key])
    return env


# ---------------------------------------------------------------------------
# Filesystem job store.
# ---------------------------------------------------------------------------

GRAPH_FILE = "dependency_graph.json"
SNIPPETS_DIR = "spdx_snippets"
PAYLOAD_FILE = "payload.json"
META_FILE = "meta.json"
STDERR_FILE = "stderr.log"
QUEUED_SENTINEL = "queued"
CLAIMED_SENTINEL = "claimed"


def _atomic_write_json(path, obj):
    tmp = f"{path}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)  # atomic on the same filesystem


class JobStore:
    """A directory of jobs on a shared volume, used as queue + result store."""

    def __init__(self, root):
        self.root = root
        os.makedirs(self.root, exist_ok=True)

    # -- paths -------------------------------------------------------------
    def job_dir(self, job_id):
        return os.path.join(self.root, job_id)

    def graph_path(self, job_id):
        return os.path.join(self.job_dir(job_id), GRAPH_FILE)

    def snippets_dir(self, job_id):
        return os.path.join(self.job_dir(job_id), SNIPPETS_DIR)

    def _meta_path(self, job_id):
        return os.path.join(self.job_dir(job_id), META_FILE)

    # -- submit ------------------------------------------------------------
    def create(self, payload):
        """Persist a validated payload and enqueue it. Returns the meta dict."""
        job_id = uuid.uuid4().hex
        d = self.job_dir(job_id)
        os.makedirs(d, exist_ok=False)
        _atomic_write_json(os.path.join(d, PAYLOAD_FILE), payload)
        meta = {
            "id": job_id,
            "status": STATUS_QUEUED,
            "repo": payload.get("repo"),
            "depth": payload.get("depth"),
            "created_at": time.time(),
            "started_at": None,
            "finished_at": None,
            "error": None,
            "returncode": None,
        }
        _atomic_write_json(self._meta_path(job_id), meta)
        # Write the queued sentinel LAST: its presence means the job is fully
        # staged and safe for a worker to claim.
        open(os.path.join(d, QUEUED_SENTINEL), "w").close()
        return meta

    # -- read --------------------------------------------------------------
    def get_meta(self, job_id):
        try:
            with open(self._meta_path(job_id)) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def get_payload(self, job_id):
        try:
            with open(os.path.join(self.job_dir(job_id), PAYLOAD_FILE)) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

    def list_metas(self, limit=100):
        metas = []
        try:
            ids = os.listdir(self.root)
        except OSError:
            return metas
        for job_id in ids:
            m = self.get_meta(job_id)
            if m:
                metas.append(m)
        metas.sort(key=lambda m: m.get("created_at") or 0, reverse=True)
        return metas[:limit]

    def delete(self, job_id):
        import shutil

        d = self.job_dir(job_id)
        if not os.path.isdir(d):
            return False
        shutil.rmtree(d, ignore_errors=True)
        return True

    # -- worker side -------------------------------------------------------
    def iter_queued_ids(self):
        """Yield ids that still carry the queued sentinel (unclaimed)."""
        try:
            ids = os.listdir(self.root)
        except OSError:
            return
        for job_id in ids:
            if os.path.exists(os.path.join(self.job_dir(job_id), QUEUED_SENTINEL)):
                yield job_id

    def try_claim(self, job_id):
        """Atomically claim a queued job. Returns True iff this caller won.

        The atomic ``rename`` of the queued sentinel is the compare-and-swap:
        exactly one worker/thread can succeed, even across processes on the
        same filesystem.
        """
        d = self.job_dir(job_id)
        try:
            os.rename(
                os.path.join(d, QUEUED_SENTINEL),
                os.path.join(d, CLAIMED_SENTINEL),
            )
        except OSError:
            return False  # already claimed or gone
        self.update_meta(
            job_id, status=STATUS_RUNNING, started_at=time.time()
        )
        return True

    def update_meta(self, job_id, **fields):
        meta = self.get_meta(job_id) or {"id": job_id}
        meta.update(fields)
        _atomic_write_json(self._meta_path(job_id), meta)
        return meta

    def write_stderr(self, job_id, text):
        try:
            with open(os.path.join(self.job_dir(job_id), STDERR_FILE), "w") as f:
                f.write(text or "")
        except OSError:
            pass
