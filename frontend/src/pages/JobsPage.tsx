import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import { TERMINAL, type JobMeta } from "../api/types";
import { StatusBadge } from "../components/Badges";
import { useNow } from "../hooks/useNow";
import { fmtAgo, fmtCount, fmtDuration } from "../lib/format";
import { Link, navigate } from "../lib/router";

/** One-line summary of a running job's latest progress event. */
export function progressSnippet(ev: JobMeta["lastEvent"]): string {
  if (!ev) return "";
  const d = ev.data as Record<string, unknown>;
  switch (ev.type) {
    case "search_progress":
      return `searching · ${fmtCount(Number(d.matches))} matches, ${fmtCount(Number(d.consumers))} repos`;
    case "enrich_progress":
      return `enriching ${d.done}/${d.total} · ${d.repo}`;
    case "candidates":
      return `${fmtCount(Number(d.total))} candidates found`;
    case "phase":
      return `${String(d.phase).replace("_", " ")} ${d.state === "start" ? "…" : "done"}`;
    case "node":
    case "edge":
      return "enriching dependents";
    case "node_start":
      return `evaluating ${d.repo}`;
    case "run_started":
      return "starting";
    case "job":
      return d.status === "running" ? "starting crawler" : "";
    default:
      return ev.type;
  }
}

export function JobsPage() {
  const [jobs, setJobs] = useState<JobMeta[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const active = (jobs ?? []).some((j) => !TERMINAL.has(j.status));
  const now = useNow(active);

  const load = useCallback(() => {
    api
      .listJobs()
      .then((j) => {
        setJobs(j);
        setError(null);
      })
      .catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!active) return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [active, load]);

  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
    } catch (e) {
      setError(String((e as Error).message));
    }
    load();
  };

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Audits</h1>
          <p className="sub">Recent audit jobs on this server. Results are kept until deleted or expired.</p>
        </div>
        <Link to="/" className="btn btn-primary">
          New audit
        </Link>
      </div>
      {error && <div className="banner danger">{error}</div>}
      <div className="card">
        {jobs === null ? (
          <div className="empty">Loading…</div>
        ) : jobs.length === 0 ? (
          <div className="empty">
            No audits yet. <Link to="/">Start one</Link>.
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Repository</th>
                  <th>Status</th>
                  <th className="num">Depth</th>
                  <th>Submitted</th>
                  <th>Duration</th>
                  <th>Progress</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {jobs.map((j) => {
                  const end = j.finished_at ?? (j.started_at ? now : null);
                  const dur = j.started_at && end ? end - j.started_at : null;
                  const terminal = TERMINAL.has(j.status);
                  return (
                    <tr key={j.id} onClick={() => navigate(`/audits/${j.id}`)}>
                      <td>
                        <Link to={`/audits/${j.id}`} className="repo" onClick={(e) => e.stopPropagation()}>
                          {j.repo ?? j.id}
                        </Link>
                        <div className="desc mono">{j.id.slice(0, 12)}</div>
                      </td>
                      <td><StatusBadge status={j.status} /></td>
                      <td className="num">{j.depth ?? 1}</td>
                      <td className="nowrap small" title={new Date(j.created_at * 1000).toLocaleString()}>
                        {fmtAgo(j.created_at, now)}
                      </td>
                      <td className="nowrap small">{fmtDuration(dur)}</td>
                      <td className="small muted truncate" style={{ maxWidth: 320 }}>
                        {terminal ? (j.error ?? "") : progressSnippet(j.lastEvent)}
                      </td>
                      <td className="right" onClick={(e) => e.stopPropagation()}>
                        {terminal ? (
                          <button
                            className="btn btn-sm btn-ghost"
                            onClick={() => {
                              if (confirm(`Delete the audit of ${j.repo}? Its results will be removed.`)) {
                                void act(() => api.remove(j.id));
                              }
                            }}
                          >
                            Delete
                          </button>
                        ) : (
                          <button className="btn btn-sm btn-ghost" onClick={() => void act(() => api.cancel(j.id))}>
                            Cancel
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
