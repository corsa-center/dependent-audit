import { useMemo } from "react";
import type { PhaseName } from "../api/events";
import { useNow } from "../hooks/useNow";
import { fmtCount, fmtDuration, fmtScore, githubUrl } from "../lib/format";
import { sortedRows, type PhaseEntry, type ProgressState } from "../state/progressReducer";
import { ConfidenceBadge, LayerLabel, RelationshipBadge } from "./Badges";

const PHASE_LABEL: Record<PhaseName, string> = {
  root_metadata: "Root metadata & citations",
  declared: "Declared registries",
  identifiers: "Compile identifier set",
  specificity: "Specificity probes",
  search: "Sourcegraph search",
  scoring: "Score consumers",
  enrich: "Enrich dependents",
  write: "Write graph",
};

function phaseDetail(p: PhaseEntry): string {
  const d = p.detail ?? {};
  switch (p.phase) {
    case "identifiers":
      return d.count != null ? `${d.count} identifiers` : "";
    case "specificity":
      return d.patterns != null ? `${d.patterns} patterns · ${d.probes ?? 0} probes` : "";
    case "search":
      return d.matches != null ? `${fmtCount(Number(d.matches))} matches · ${fmtCount(Number(d.consumers))} repos` : "";
    case "declared":
      return d.aliases != null ? `${d.aliases} aliases` : "";
    case "enrich":
    case "scoring":
      return d.total != null ? `${fmtCount(Number(d.total))} repos` : d.consumers != null ? `${fmtCount(Number(d.consumers))} repos` : "";
    default:
      return "";
  }
}

const LIVE_ROW_CAP = 500;

export function LiveProgress({ state, active }: { state: ProgressState; active: boolean }) {
  const now = useNow(active);
  const rows = useMemo(() => sortedRows(state), [state]);
  const phases = state.phases.slice(-12);
  const elapsed = state.startedAt ? (state.finishedAt ?? now) - state.startedAt : null;
  const enrichPct = state.enrich ? (100 * state.enrich.done) / Math.max(1, state.enrich.total) : 0;
  const warnings = state.logs.filter((l) => l.level === "WARNING" || l.level === "ERROR" || l.level === "CRITICAL");
  const enriched = rows.filter((r) => r.enriched).length;

  return (
    <div className="stack">
      <div className="stats">
        <div className="stat">
          <div className="label">Elapsed</div>
          <div className="value">{fmtDuration(elapsed)}</div>
          <div className="hint">{state.status === "queued" ? "waiting for a worker" : state.current ? `node ${state.current.processed}${state.current.queued ? ` · ${state.current.queued} queued` : ""}` : "starting"}</div>
        </div>
        <div className="stat">
          <div className="label">Search matches</div>
          <div className="value">{fmtCount(state.search?.matches ?? 0)}</div>
          <div className="hint">{state.search ? (state.search.final ? "search complete" : `${fmtDuration(state.search.elapsedSec)} streaming`) : "—"}</div>
        </div>
        <div className="stat">
          <div className="label">Dependents found</div>
          <div className="value">{fmtCount(Math.max(rows.length, state.search?.consumers ?? 0))}</div>
          <div className="hint">{rows.length ? `${enriched} enriched` : "—"}</div>
        </div>
        <div className="stat">
          <div className="label">Edges</div>
          <div className="value">{fmtCount(state.edges.length)}</div>
          <div className="hint">{warnings.length ? `${warnings.length} warning${warnings.length > 1 ? "s" : ""}` : "no warnings"}</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-head">
            <h2>Dependents (live)</h2>
            <span className="small muted">
              {rows.length > LIVE_ROW_CAP ? `top ${LIVE_ROW_CAP} of ${fmtCount(rows.length)}` : `${rows.length}`}
            </span>
          </div>
          {state.enrich && (
            <div className="card-pad" style={{ paddingTop: 10, paddingBottom: 10, borderBottom: "1px solid var(--border)" }}>
              <div className="row small" style={{ justifyContent: "space-between", marginBottom: 6 }}>
                <span className="truncate">Enriching <strong>{state.enrich.repo}</strong></span>
                <span className="muted nowrap">{state.enrich.done} / {state.enrich.total}</span>
              </div>
              <div className="bar"><span style={{ width: `${enrichPct}%` }} /></div>
            </div>
          )}
          {rows.length === 0 ? (
            <div className="empty">
              {state.status === "queued" ? "Queued…" : "Dependents appear here as soon as the search finishes."}
            </div>
          ) : (
            <div className="table-wrap" style={{ maxHeight: 520 }}>
              <table className="data">
                <thead>
                  <tr>
                    <th>Repository</th>
                    <th>Confidence</th>
                    <th>Relationship</th>
                    <th>Evidence</th>
                    <th className="num">Matches</th>
                    <th className="num">Stars</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.slice(0, LIVE_ROW_CAP).map((r) => (
                    <tr key={r.id} className={r.enriched ? undefined : "pending"} style={{ cursor: "default" }}>
                      <td>
                        <a className="repo" href={githubUrl(r.id)} target="_blank" rel="noreferrer">{r.id}</a>
                        {r.node?.description && <div className="desc truncate">{r.node.description}</div>}
                      </td>
                      <td className="nowrap">
                        <ConfidenceBadge value={r.confidence} score={r.confidenceScore} />{" "}
                        <span className="faint small mono">{fmtScore(r.confidenceScore)}</span>
                      </td>
                      <td><RelationshipBadge value={r.relationship} /></td>
                      <td className="small nowrap"><LayerLabel layer={r.evidenceLayer} /></td>
                      <td className="num">{fmtCount(r.matchCount)}</td>
                      <td className="num">{r.enriched ? fmtCount(r.node?.stars) : <span className="faint">…</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="stack">
          <div className="card card-pad">
            <h3 style={{ marginBottom: 10 }}>Phases</h3>
            {phases.length === 0 ? (
              <p className="small muted">{state.status === "queued" ? "Waiting for a worker…" : "Starting…"}</p>
            ) : (
              <ol className="timeline">
                {phases.map((p, i) => (
                  <li key={`${p.phase}-${p.repo}-${p.startTs}-${i}`} className={p.state}>
                    <span className="tick" />
                    <span>
                      {PHASE_LABEL[p.phase] ?? p.phase}
                      {p.repo && p.repo !== state.root && <span className="faint small"> · {p.repo}</span>}
                      <div className="detail">{phaseDetail(p)}</div>
                    </span>
                    <span className="small faint nowrap">
                      {fmtDuration(Math.max(0, (p.state === "running" ? now : (p.endTs ?? p.startTs)) - p.startTs))}
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </div>

          {(warnings.length > 0 || state.incomplete.length > 0) && (
            <div className="card card-pad">
              <h3 style={{ marginBottom: 10 }}>Warnings</h3>
              <ul className="small" style={{ margin: 0, paddingLeft: 18, maxHeight: 260, overflow: "auto" }}>
                {state.incomplete.map((w, i) => (
                  <li key={`inc-${i}`} style={{ color: "var(--warn)" }}>
                    Incomplete {w.scope}{w.repo ? ` (${w.repo})` : ""}: {w.reason}
                  </li>
                ))}
                {warnings.slice(-50).map((w, i) => (
                  <li key={`log-${i}`}>
                    <span className="mono faint">{w.level}</span> {w.message}
                    {w.repo && <span className="faint"> · {w.repo}</span>}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
