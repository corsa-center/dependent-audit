"""Shared building blocks for the audit service.

Both the web API (``app.py``) and the worker (``worker.py``) import this module.
It owns three things:

1. The payload -> CLI-argv mapping (the request schema). It is declared once in
   :data:`OPTION_SPEC`, which also drives the frontend form via
   ``GET /api/options``; a unit test checks it against the crawler's argparse
   parser so the two cannot silently drift.
2. A small filesystem-backed :class:`JobStore` used as a shared queue + result
   store, so the web tier and the worker tier communicate purely through a
   shared volume — no broker/DB dependency.
3. The per-job progress event log (``events.jsonl``): an append-only JSON Lines
   file written by the web tier (``queued``), the worker (lifecycle), and the
   crawler (``--events-file``), and tailed by the SSE endpoint.

Each job lives in ``<jobs_dir>/<id>/``:

    payload.json            the (normalized) request
    meta.json               {id, status, timestamps, error, returncode}
    queued                  sentinel; atomically renamed to `claimed` on pickup
    claimed                 sentinel present once a worker owns the job; its
                            mtime is the worker's per-job heartbeat
    cancel                  sentinel; asks the worker to stop the crawl
    events.jsonl            progress events (see deploy/README.md)
    dependency_graph.json   the crawler output (on success)
    spdx_snippets/          per-edge SPDX snippets (on success)
    stderr.log              the crawler's log, written while it runs

Status flows: queued -> running -> (succeeded | failed | timeout | cancelled).
"""

import json
import os
import shutil
import sys
import time
import uuid

# ---------------------------------------------------------------------------
# Payload -> CLI mapping. Payload key == flag name minus "--", underscored.
# ---------------------------------------------------------------------------

# kind: str | int | float | flag | choice. `group` lays out the frontend form.
OPTION_SPEC = [
    # -- basic ---------------------------------------------------------------
    {
        "key": "repo",
        "flag": "--repo",
        "kind": "str",
        "group": "basic",
        "required": True,
        "help": "Root repository to audit, as owner/name.",
    },
    {
        "key": "name",
        "flag": "--name",
        "kind": "str",
        "group": "basic",
        "required": True,
        "help": "Short project name (used to derive identifiers).",
    },
    {
        "key": "depth",
        "flag": "--depth",
        "kind": "int",
        "group": "basic",
        "default": 1,
        "min": 0,
        "help": "Crawl depth. 0 audits only the root's metadata/citations.",
    },
    {
        "key": "no_citations",
        "flag": "--no-citations",
        "kind": "flag",
        "group": "basic",
        "help": "Skip academic citation mining (much faster pure dependency graph).",
    },
    {
        "key": "sg_count",
        "flag": "--sg-count",
        "kind": "str",
        "group": "basic",
        "default": "5000",
        "help": "Max Sourcegraph matches per node: an integer or 'all'.",
    },
    # -- discovery -----------------------------------------------------------
    {
        "key": "ecosystem",
        "flag": "--ecosystem",
        "kind": "choice",
        "group": "discovery",
        "default": "cpp",
        "choices": ["cpp"],
        "help": "Ecosystem plugin (only C/C++ is implemented).",
    },
    {
        "key": "no_defaults",
        "flag": "--no-defaults",
        "kind": "flag",
        "group": "discovery",
        "help": "Drop the auto-compiled identifier set; search only the custom string.",
    },
    {
        "key": "custom_string",
        "flag": "--custom-string",
        "kind": "str",
        "group": "discovery",
        "help": "Extra consumer-side regex (RE2/Python), used verbatim as an ALIAS.",
    },
    {
        "key": "custom_file",
        "flag": "--custom-file",
        "kind": "str",
        "group": "discovery",
        "help": "Limit the search to this filename pattern.",
    },
    {
        "key": "declared_sources",
        "flag": "--declared-sources",
        "kind": "str",
        "group": "discovery",
        "help": "Comma-separated registries to corroborate against (e.g. 'spack').",
    },
    {
        "key": "forks",
        "flag": "--forks",
        "kind": "flag",
        "group": "discovery",
        "help": "Include forks in the search.",
    },
    {
        "key": "include_archived",
        "flag": "--include-archived",
        "kind": "flag",
        "group": "discovery",
        "help": "Include archived repositories.",
    },
    {
        "key": "include_vendored",
        "flag": "--include-vendored",
        "kind": "flag",
        "group": "discovery",
        "help": "Include matches inside vendored/third-party directories.",
    },
    {
        "key": "no_idf",
        "flag": "--no-idf",
        "kind": "flag",
        "group": "discovery",
        "help": "Disable IDF specificity gating of generic identifier tokens.",
    },
    {
        "key": "idf_cap",
        "flag": "--idf-cap",
        "kind": "int",
        "group": "discovery",
        "default": 300,
        "min": 1,
        "help": "Frequency-probe cap; tokens at/above it are treated as generic.",
    },
    {
        "key": "sg_delay",
        "flag": "--sg-delay",
        "kind": "float",
        "group": "discovery",
        "default": 0.0,
        "min": 0,
        "help": "Seconds to wait before each Sourcegraph search (throttle).",
    },
    # -- citations -----------------------------------------------------------
    {
        "key": "email",
        "flag": "--email",
        "kind": "str",
        "group": "citations",
        "help": "Contact email for the OpenAlex/Crossref polite pool.",
    },
    {
        "key": "academic_keyword",
        "flag": "--academic-keyword",
        "kind": "str",
        "group": "citations",
        "help": "Comma-separated full-text search keywords (root node only).",
    },
    {
        "key": "citation_depth",
        "flag": "--citation-depth",
        "kind": "int",
        "group": "citations",
        "default": 1,
        "min": 1,
        "help": "Reverse-citation crawl hops at the root (1 = direct citers).",
    },
    {
        "key": "paper_relevance_floor",
        "flag": "--paper-relevance-floor",
        "kind": "choice",
        "group": "citations",
        "default": "medium",
        "choices": ["low", "medium", "high"],
        "help": "Lowest paper relevance tier kept in the output.",
    },
    {
        "key": "no_paper_filter",
        "flag": "--no-paper-filter",
        "kind": "flag",
        "group": "citations",
        "help": "Keep low-relevance papers (scored, not dropped).",
    },
    {
        "key": "no_paper_relevance",
        "flag": "--no-paper-relevance",
        "kind": "flag",
        "group": "citations",
        "help": "Disable paper relevance scoring (historical behavior).",
    },
    # No form defaults: blank means the worker's environment default
    # (CITATION_GRAPH_DEPTH / OPENALEX_DELAY in .env) applies.
    {
        "key": "citation_graph_depth",
        "flag": "--citation-graph-depth",
        "kind": "int",
        "group": "citations",
        "min": 0,
        "help": "Deepest graph level that gets paper/citation analysis "
        "(1 = root + direct consumers). Blank = server default.",
    },
    {
        "key": "openalex_delay",
        "flag": "--openalex-delay",
        "kind": "float",
        "group": "citations",
        "min": 0,
        "help": "Seconds to wait before each OpenAlex request (throttle). "
        "Blank = server default.",
    },
    # -- advanced ------------------------------------------------------------
    {
        "key": "verbose",
        "flag": "--verbose",
        "kind": "flag",
        "group": "advanced",
        "help": "Structured JSON crawler logs.",
    },
]

OPTIONS_BY_KEY = {o["key"]: o for o in OPTION_SPEC}

# Derived views, kept for the argv builder and existing callers.
STRING_OPTS = {o["key"]: o["flag"] for o in OPTION_SPEC if o["kind"] == "str"}
CHOICE_OPTS = {o["key"]: o["flag"] for o in OPTION_SPEC if o["kind"] == "choice"}
INT_OPTS = {o["key"]: o["flag"] for o in OPTION_SPEC if o["kind"] == "int"}
FLOAT_OPTS = {o["key"]: o["flag"] for o in OPTION_SPEC if o["kind"] == "float"}
FLAG_OPTS = {o["key"]: o["flag"] for o in OPTION_SPEC if o["kind"] == "flag"}

# Secrets: forwarded via the subprocess env (never the command line, which would
# leak into the process table). The CLI reads these env vars as flag defaults.
TOKEN_ENV = {
    "sg_token": "SG_TOKEN",
    "gh_token": "GH_TOKEN",
    "openalex_api_key": "OPENALEX_API_KEY",
}

# Crawler flags a client must never set: local filesystem paths the crawler
# reads or writes (would let a caller touch anything the service user can) and
# an outbound URL (SSRF). Accepted and silently dropped for backwards
# compatibility.
SERVER_ONLY = {
    "idf_cache",
    "paper_cache",
    "relevance_llm_url",
    "relevance_llm_model",
    "config",
    "repo_checkout",
}


def _pinned_argv():
    """Server-controlled flags passed explicitly on every run.

    The crawler merges an auto-fetched ``.dependent-audit.toml`` from the
    *target* repo into any option not given on the command line, so anything
    left implicit could be steered by whoever owns the audited repo. Passing
    these explicitly claims them: caches stay inside the job dir (the cwd) and
    the relevance-LLM endpoint comes only from the worker's environment."""
    return [
        "--idf-cache",
        ".idf_cache.json",
        "--paper-cache",
        ".paper_cache.json",
        "--relevance-llm-url",
        os.environ.get("RELEVANCE_LLM_URL", ""),
        "--relevance-llm-model",
        os.environ.get("RELEVANCE_LLM_MODEL", "local-model"),
    ]


REQUIRED = tuple(o["key"] for o in OPTION_SPEC if o.get("required"))

# Path to the crawler; overridable so the image layout can change freely.
AUDIT_SCRIPT = os.environ.get(
    "AUDIT_SCRIPT", os.path.join(os.path.dirname(__file__), "audit_dependents.py")
)

# Service-only payload keys that are not passed through to the CLI.
SERVICE_KEYS = {"out", "include_spdx"}

KNOWN_KEYS = set(OPTIONS_BY_KEY) | set(TOKEN_ENV) | SERVICE_KEYS | SERVER_ONLY

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_TIMEOUT = "timeout"
STATUS_CANCELLED = "cancelled"
TERMINAL_STATUSES = {STATUS_SUCCEEDED, STATUS_FAILED, STATUS_TIMEOUT, STATUS_CANCELLED}


def payload_tokens_allowed():
    """Per-request tokens are a multi-tenant escape hatch; production
    deployments should set ALLOW_PAYLOAD_TOKENS=0 so only server tokens run."""
    return truthy(os.environ.get("ALLOW_PAYLOAD_TOKENS", "1"))


def normalize(payload):
    """Accept hyphenated or underscored keys; return an underscored copy."""
    return {str(k).replace("-", "_"): v for k, v in (payload or {}).items()}


def truthy(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def redact(payload):
    """A copy of the payload safe to show a client: secrets masked, server-only
    keys dropped."""
    out = {}
    for k, v in (payload or {}).items():
        if k in SERVER_ONLY:
            continue
        out[k] = "***" if k in TOKEN_ENV and v else v
    return out


def public_options():
    """The option spec as served to the frontend (no secrets/server-only keys)."""
    return [dict(o) for o in OPTION_SPEC]


def validate(payload):
    """Raise ValueError if the (normalized) payload is malformed.

    Runs the same checks and type coercions as :func:`build_argv` so a bad
    request is rejected at submit time with a 400 rather than failing later in
    the worker.
    """
    if not payload_tokens_allowed():
        sent = [k for k in TOKEN_ENV if payload.get(k)]
        if sent:
            raise ValueError(
                f"per-request tokens are disabled on this server: {', '.join(sent)}"
            )
    build_argv(payload, out_path="/dev/null")


def _check_min(key, value):
    lo = OPTIONS_BY_KEY[key].get("min")
    if lo is not None and value < lo:
        raise ValueError(f"'{key}' must be >= {lo}")


def build_argv(payload, out_path, events_file=None):
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

    sg_count = payload.get("sg_count")
    if sg_count not in (None, ""):
        s = str(sg_count).strip().lower()
        if s != "all" and not s.isdigit():
            raise ValueError("'sg_count' must be a positive integer or 'all'")

    for key, flag in CHOICE_OPTS.items():
        if payload.get(key) not in (None, ""):
            value = str(payload[key])
            choices = OPTIONS_BY_KEY[key]["choices"]
            if value not in choices:
                raise ValueError(f"'{key}' must be one of: {', '.join(choices)}")
            argv += [flag, value]

    for key, flag in INT_OPTS.items():
        if payload.get(key) not in (None, ""):
            try:
                value = int(payload[key])
            except (TypeError, ValueError):
                raise ValueError(f"'{key}' must be an integer")
            _check_min(key, value)
            argv += [flag, str(value)]

    for key, flag in FLOAT_OPTS.items():
        if payload.get(key) not in (None, ""):
            try:
                value = float(payload[key])
            except (TypeError, ValueError):
                raise ValueError(f"'{key}' must be a number")
            _check_min(key, value)
            argv += [flag, str(value)]

    for key, flag in FLAG_OPTS.items():
        if key in payload and truthy(payload[key]):
            argv.append(flag)

    argv += _pinned_argv()
    # The service owns the output locations; any client "out" is ignored.
    argv += ["--out", out_path]
    if events_file:
        argv += ["--events-file", events_file]
    return argv


def build_env(payload, base_env=None):
    env = dict(base_env if base_env is not None else os.environ)
    if payload_tokens_allowed():
        for key, env_name in TOKEN_ENV.items():
            if payload.get(key):
                env[env_name] = str(payload[key])
    return env


# ---------------------------------------------------------------------------
# Progress events (JSON Lines). Same envelope as the crawler's ProgressEmitter:
#   {"seq", "ts", "type", "src", "data"}
# `seq` is the line index; the SSE endpoint uses the line index as the event id.
# ---------------------------------------------------------------------------

HEARTBEAT = object()  # sentinel yielded by tail_events when idle


def count_lines(path):
    try:
        with open(path, "rb") as f:
            return sum(chunk.count(b"\n") for chunk in iter(lambda: f.read(65536), b""))
    except OSError:
        return 0


def append_event(path, type_, src, **data):
    """Append one event as a single O_APPEND write. Never raises."""
    try:
        line = (
            json.dumps(
                {
                    "seq": count_lines(path),
                    "ts": round(time.time(), 3),
                    "type": type_,
                    "src": src,
                    "data": data,
                },
                separators=(",", ":"),
                default=str,
            )
            + "\n"
        )
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            buf = line.encode()
            while buf:
                buf = buf[os.write(fd, buf) :]
        finally:
            os.close(fd)
    except OSError:
        pass


def is_terminal_event(ev):
    return (
        isinstance(ev, dict)
        and ev.get("type") == "job"
        and (ev.get("data") or {}).get("status") in TERMINAL_STATUSES
    )


def tail_events(
    path,
    start=0,
    *,
    poll=0.5,
    heartbeat=15.0,
    max_seconds=None,
    should_stop=None,
    clock=time.monotonic,
    sleep=time.sleep,
):
    """Follow a JSON Lines event file, yielding ``(index, raw_line, event)``
    for every line at or after ``start``, or :data:`HEARTBEAT` after
    ``heartbeat`` idle seconds.

    A partially written trailing line is buffered until its newline arrives. A
    corrupt line still consumes its index (``event`` is ``None``) so ids stay
    stable across reconnects. Stops when the file is missing/deleted, after
    ``max_seconds``, or when ``should_stop()`` returns true. The caller decides
    when the stream is logically finished (e.g. on a terminal job event).
    """
    t0 = clock()
    try:
        f = open(path, "rb")
    except OSError:
        return
    with f:
        idx, pending, last_out = 0, b"", clock()
        while True:
            chunk = f.read(65536)
            if chunk:
                pending += chunk
                *lines, pending = pending.split(b"\n")
                for raw in lines:
                    i, idx = idx, idx + 1
                    if i < start:
                        continue
                    text = raw.decode("utf-8", "replace")
                    try:
                        ev = json.loads(text)
                    except ValueError:
                        ev = None
                    last_out = clock()
                    yield i, text, ev
                continue
            now = clock()
            if max_seconds is not None and now - t0 >= max_seconds:
                return
            if should_stop is not None and should_stop():
                return
            if not os.path.exists(path):
                return
            if now - last_out >= heartbeat:
                last_out = now
                yield HEARTBEAT
            sleep(poll)


def read_last_event(path, max_bytes=16384):
    """The last parsable event in the file, reading only its tail."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read()
    except OSError:
        return None
    for raw in reversed(data.split(b"\n")):
        if not raw.strip():
            continue
        try:
            return json.loads(raw)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Filesystem job store.
# ---------------------------------------------------------------------------

GRAPH_FILE = "dependency_graph.json"
SNIPPETS_DIR = "spdx_snippets"
PAYLOAD_FILE = "payload.json"
META_FILE = "meta.json"
STDERR_FILE = "stderr.log"
EVENTS_FILE = "events.jsonl"
QUEUED_SENTINEL = "queued"
CLAIMED_SENTINEL = "claimed"
CANCEL_SENTINEL = "cancel"
WORKER_STATE_FILE = ".worker.json"


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

    def events_path(self, job_id):
        return os.path.join(self.job_dir(job_id), EVENTS_FILE)

    def log_path(self, job_id):
        return os.path.join(self.job_dir(job_id), STDERR_FILE)

    def _meta_path(self, job_id):
        return os.path.join(self.job_dir(job_id), META_FILE)

    def _sentinel(self, job_id, name):
        return os.path.join(self.job_dir(job_id), name)

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
            "name": payload.get("name"),
            "depth": payload.get("depth"),
            "created_at": time.time(),
            "started_at": None,
            "finished_at": None,
            "error": None,
            "returncode": None,
        }
        _atomic_write_json(self._meta_path(job_id), meta)
        self.append_event(
            job_id,
            "job",
            "web",
            status=STATUS_QUEUED,
            jobId=job_id,
            repo=meta["repo"],
            name=meta["name"],
            depth=meta["depth"],
        )
        # Write the queued sentinel LAST: its presence means the job is fully
        # staged and safe for a worker to claim.
        open(self._sentinel(job_id, QUEUED_SENTINEL), "w").close()
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
        d = self.job_dir(job_id)
        if not os.path.isdir(d):
            return False
        shutil.rmtree(d, ignore_errors=True)
        return True

    # -- events ------------------------------------------------------------
    def append_event(self, job_id, type_, src, **data):
        append_event(self.events_path(job_id), type_, src, **data)

    def event_count(self, job_id):
        return count_lines(self.events_path(job_id))

    def last_event(self, job_id):
        return read_last_event(self.events_path(job_id))

    # -- cancel ------------------------------------------------------------
    def request_cancel(self, job_id):
        open(self._sentinel(job_id, CANCEL_SENTINEL), "w").close()

    def cancel_requested(self, job_id):
        return os.path.exists(self._sentinel(job_id, CANCEL_SENTINEL))

    # -- worker side -------------------------------------------------------
    def iter_queued_ids(self):
        """Yield ids that still carry the queued sentinel (unclaimed)."""
        try:
            ids = os.listdir(self.root)
        except OSError:
            return
        for job_id in ids:
            if os.path.exists(self._sentinel(job_id, QUEUED_SENTINEL)):
                yield job_id

    def try_claim(self, job_id, status=STATUS_RUNNING):
        """Atomically claim a queued job. Returns True iff this caller won.

        The atomic ``rename`` of the queued sentinel is the compare-and-swap:
        exactly one worker/thread can succeed, even across processes on the
        same filesystem. (The web tier also claims, to cancel a queued job.)
        """
        try:
            os.rename(
                self._sentinel(job_id, QUEUED_SENTINEL),
                self._sentinel(job_id, CLAIMED_SENTINEL),
            )
        except OSError:
            return False  # already claimed or gone
        self.update_meta(job_id, status=status, started_at=time.time())
        return True

    def touch_claim(self, job_id):
        """Per-job heartbeat: the claimed sentinel's mtime."""
        try:
            os.utime(self._sentinel(job_id, CLAIMED_SENTINEL))
        except OSError:
            pass

    def claim_age(self, job_id):
        try:
            return time.time() - os.path.getmtime(
                self._sentinel(job_id, CLAIMED_SENTINEL)
            )
        except OSError:
            return None

    def update_meta(self, job_id, **fields):
        meta = self.get_meta(job_id) or {"id": job_id}
        meta.update(fields)
        _atomic_write_json(self._meta_path(job_id), meta)
        return meta

    def write_stderr(self, job_id, text):
        try:
            with open(self.log_path(job_id), "a") as f:
                f.write(text or "")
        except OSError:
            pass

    def read_log_tail(self, job_id, lines=200, max_bytes=262144):
        try:
            with open(self.log_path(job_id), "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - max_bytes))
                data = f.read().decode("utf-8", "replace")
        except OSError:
            return None
        return "\n".join(data.splitlines()[-lines:])

    # -- worker liveness -----------------------------------------------------
    def write_worker_state(self, state):
        try:
            _atomic_write_json(os.path.join(self.root, WORKER_STATE_FILE), state)
        except OSError:
            pass

    def read_worker_state(self):
        try:
            with open(os.path.join(self.root, WORKER_STATE_FILE)) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
