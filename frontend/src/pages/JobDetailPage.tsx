import { useEffect, useState } from "react";
import { api, ApiError, links } from "../api/client";
import { TERMINAL, type Graph, type JobMeta } from "../api/types";
import { StatusBadge } from "../components/Badges";
import { GraphResults } from "../components/GraphResults";
import { LiveProgress } from "../components/LiveProgress";
import { useJobEvents } from "../hooks/useJobEvents";
import { fmtDuration, fmtTimestamp } from "../lib/format";
import { Link, navigate } from "../lib/router";

function Params({ params }: { params: Record<string, unknown> | undefined }) {
  const entries = Object.entries(params ?? {}).filter(([k]) => k !== "repo" && k !== "name");
  if (!entries.length) return <span className="small faint">default options</span>;
  return (
    <div className="tags">
      {entries.map(([k, v]) => (
        <span key={k} className="tag">
          {v === true ? `--${k.replace(/_/g, "-")}` : `--${k.replace(/_/g, "-")} ${String(v)}`}
        </span>
      ))}
    </div>
  );
}

function LogTail({ jobId, open = false }: { jobId: string; open?: boolean }) {
  const [text, setText] = useState<string | null>(null);
  const [shown, setShown] = useState(open);
  useEffect(() => {
    if (shown && text === null) void api.log(jobId, 400).then(setText);
  }, [shown, text, jobId]);
  return (
    <details className="card card-pad" open={open} onToggle={(e) => setShown((e.target as HTMLDetailsElement).open)}>
      <summary style={{ cursor: "pointer", fontWeight: 650 }}>Crawler log</summary>
      <pre className="log" style={{ marginTop: 12 }}>{text === null ? "Loading…" : text || "(empty)"}</pre>
    </details>
  );
}

export function JobDetailPage({ id }: { id: string }) {
  const [meta, setMeta] = useState<JobMeta | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [graphError, setGraphError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { state, stream } = useJobEvents(id);

  const status = state.status ?? meta?.status ?? null;
  const terminal = status != null && TERMINAL.has(status);

  // Initial load, and a refresh whenever the stream reports a new status.
  useEffect(() => {
    api
      .getJob(id)
      .then(setMeta)
      .catch((e) => {
        if (e instanceof ApiError && e.status === 404) setNotFound(true);
      });
  }, [id, state.status]);

  useEffect(() => {
    if (meta?.status !== "succeeded" || graph) return;
    api
      .graph(id)
      .then(setGraph)
      .catch((e: Error) => setGraphError(e.message));
  }, [id, meta?.status, graph]);

  if (notFound) {
    return (
      <div className="stack">
        <div className="banner danger">This audit doesn't exist (it may have been deleted or expired).</div>
        <Link to="/audits">Back to audits</Link>
      </div>
    );
  }

  const repo = meta?.repo ?? state.root ?? "…";
  const started = meta?.started_at ?? state.startedAt;
  const finished = meta?.finished_at ?? state.finishedAt;

  const cancel = async () => {
    setBusy(true);
    try {
      await api.cancel(id);
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!confirm(`Delete this audit of ${repo}? Its results will be removed.`)) return;
    await api.remove(id);
    navigate("/audits");
  };

  return (
    <div className="stack">
      <div className="page-head">
        <div className="head-main">
          <div className="small muted">
            <Link to="/audits">Audits</Link> / <span className="mono">{id.slice(0, 12)}</span>
          </div>
          <div className="row" style={{ marginTop: 4 }}>
            <h1 style={{ overflowWrap: "anywhere" }}>{repo}</h1>
            <StatusBadge status={status} />
            {stream === "reconnecting" && !terminal && <span className="badge pulse">reconnecting…</span>}
          </div>
          <div className="row small muted" style={{ marginTop: 6, gap: 16 }}>
            <span>Submitted {fmtTimestamp(meta?.created_at)}</span>
            {started && finished && <span>Ran {fmtDuration(finished - started)}</span>}
            {meta && <Params params={meta.params} />}
          </div>
        </div>
        <div className="row">
          {!terminal && (
            <button className="btn btn-danger" onClick={cancel} disabled={busy}>
              Cancel
            </button>
          )}
          {terminal && (
            <button className="btn" onClick={remove}>
              Delete
            </button>
          )}
        </div>
      </div>

      {status === "succeeded" ? (
        graph ? (
          <GraphResults
            graph={graph}
            graphHref={links.graphDownload(id)}
            spdxHref={meta?.hasSpdx ? links.spdx(id) : undefined}
            loadSnippet={meta?.hasSpdx ? (p) => api.snippet(id, p) : undefined}
          />
        ) : graphError ? (
          <div className="banner danger">Couldn't load the graph: {graphError}</div>
        ) : (
          <div className="empty">Loading results…</div>
        )
      ) : (
        <>
          {terminal && (
            <div className="banner danger">
              <div>
                <strong>
                  {status === "cancelled"
                    ? "Audit cancelled."
                    : status === "timeout"
                      ? "Audit timed out."
                      : "Audit failed."}
                </strong>{" "}
                {state.crawlerError?.message ?? meta?.error ?? state.error ?? ""}
                {meta?.returncode != null && meta.returncode !== 0 && (
                  <span className="muted"> (exit code {meta.returncode})</span>
                )}
                {state.edges.length > 0 && (
                  <div className="small" style={{ marginTop: 4 }}>
                    Partial progress is shown below; no graph file was produced.
                  </div>
                )}
              </div>
            </div>
          )}
          <LiveProgress state={state} active={!terminal} />
        </>
      )}

      {status && status !== "queued" && <LogTail jobId={id} open={terminal && status !== "succeeded"} />}
    </div>
  );
}
