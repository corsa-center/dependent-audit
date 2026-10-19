import { useEffect, useMemo, useState } from "react";
import type { GraphEdge, Paper } from "../api/types";
import { fmtCount, fmtDate, fmtScore, githubUrl, shortSha } from "../lib/format";
import { downloadBlob, LAYER_NAMES, TIER_RANK, type GraphModel } from "../lib/graph";
import { ConfidenceBadge, LayerLabel, PaperTierBadge, RelationshipBadge } from "./Badges";

/** Resolves a node's `snippetPath` to its SPDX document. */
export type SnippetLoader = (snippetPath: string) => Promise<unknown>;

interface Props {
  model: GraphModel;
  id: string;
  onClose: () => void;
  onSelect: (id: string) => void;
  loadSnippet?: SnippetLoader;
}

function SpdxSection({ path, load }: { path: string; load: SnippetLoader }) {
  const [doc, setDoc] = useState<unknown>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const name = path.split("/").pop() ?? path;
  const show = () => {
    setLoading(true);
    setError(null);
    load(path)
      .then(setDoc)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  };
  const text = doc == null ? "" : JSON.stringify(doc, null, 2);
  return (
    <section className="stack" style={{ gap: 8 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h3>SPDX manifest</h3>
        <div className="row">
          {doc == null ? (
            <button className="btn btn-sm" onClick={show} disabled={loading}>
              {loading ? "Loading…" : "Show"}
            </button>
          ) : (
            <button className="btn btn-sm" onClick={() => downloadBlob(name, text, "application/json")}>
              Download
            </button>
          )}
        </div>
      </div>
      <span className="mono small faint">{name}</span>
      {error && <div className="banner danger small">{error}</div>}
      {doc != null && <pre className="log">{text}</pre>}
    </section>
  );
}

function EvidenceList({ evidence }: { evidence: Record<string, unknown> | undefined }) {
  const entries = Object.entries(evidence ?? {}).sort((a, b) => Number(b[1]) - Number(a[1]));
  if (!entries.length) return <span className="faint">—</span>;
  return (
    <div className="tags">
      {entries.map(([k, v]) => (
        <span key={k} className="tag">
          {k} ×{String(v)}
        </span>
      ))}
    </div>
  );
}

function EdgeLine({ edge, other, onSelect }: { edge: GraphEdge; other: string; onSelect: (id: string) => void }) {
  return (
    <li className="row" style={{ gap: 6 }}>
      <button className="btn btn-sm btn-ghost" style={{ padding: 0 }} onClick={() => onSelect(other)}>
        {other}
      </button>
      <ConfidenceBadge value={edge.confidence} score={edge.confidenceScore} />
      {edge.relationship && edge.relationship !== "DEPENDS_ON" && (
        <RelationshipBadge value={edge.relationship} />
      )}
    </li>
  );
}

function PaperItem({ p }: { p: Paper }) {
  const href = p.url || (p.doi ? `https://doi.org/${p.doi}` : undefined);
  const ev = (p.relevanceEvidence ?? {}) as Record<string, unknown>;
  const evBits = Object.entries(ev)
    .filter(([, v]) => v != null && v !== "" && !(Array.isArray(v) && !v.length))
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.slice(0, 4).join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v)}`);
  return (
    <div className="paper">
      <div className="row" style={{ justifyContent: "space-between", alignItems: "flex-start", flexWrap: "nowrap" }}>
        <span className="title">
          {href ? (
            <a href={href} target="_blank" rel="noreferrer">
              {p.title || p.doi}
            </a>
          ) : (
            p.title || p.doi
          )}
        </span>
        <PaperTierBadge tier={p.relevanceTier} />
      </div>
      <div className="small muted">
        {[p.authors?.slice(0, 3).join(", ") + ((p.authors?.length ?? 0) > 3 ? " et al." : ""), p.journal, p.year]
          .filter(Boolean)
          .join(" · ")}
      </div>
      <div className="row small" style={{ gap: 6 }}>
        <span className="badge">{p.relation === "seminal" ? "seminal" : `citing · hop ${p.citationDepth ?? "?"}`}</span>
        {(p.provenance ?? [])
          .filter((pr) => !(pr === "seminal" && p.relation === "seminal"))
          .map((pr) => (
            <span key={pr} className="tag">{pr}</span>
          ))}
        {p.relevanceScore != null && <span className="faint mono">score {fmtScore(p.relevanceScore)}</span>}
        {p.doi && <span className="faint mono">{p.doi}</span>}
      </div>
      {evBits.length > 0 && <div className="small faint">{evBits.join(" · ")}</div>}
    </div>
  );
}

export function NodeDrawer({ model, id, onClose, onSelect, loadSnippet }: Props) {
  const node = model.nodesById.get(id);
  const d = node?.data ?? {};
  const [tier, setTier] = useState<string>("all");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const papers = useMemo(() => {
    const list = [...(d.papers ?? [])].sort(
      (a, b) =>
        (TIER_RANK[b.relevanceTier ?? ""] ?? 0) - (TIER_RANK[a.relevanceTier ?? ""] ?? 0) ||
        (b.relevanceScore ?? 0) - (a.relevanceScore ?? 0),
    );
    return tier === "all" ? list : list.filter((p) => (p.relevanceTier ?? "unknown") === tier);
  }, [d.papers, tier]);

  if (!node) return null;
  const out = model.edgesBySource.get(id) ?? [];
  const inc = model.edgesByTarget.get(id) ?? [];
  const diag = (d.paperDiagnostics ?? {}) as { complete?: boolean; warnings?: string[]; doisSeen?: number; skipped?: string };
  const isRoot = id === model.rootId;

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Details for ${id}`}>
        <div className="drawer-head">
          <div className="grow">
            <div className="small muted">{isRoot ? "Root project" : `Dependent · depth ${d.depth ?? "?"}`}</div>
            <h2 style={{ overflowWrap: "anywhere" }}>
              <a href={githubUrl(d.originUrl || id)} target="_blank" rel="noreferrer">
                {id}
              </a>
            </h2>
            {!isRoot && (
              <div className="row" style={{ marginTop: 8 }}>
                <ConfidenceBadge value={d.confidence} score={d.confidenceScore} />
                <RelationshipBadge value={d.relationship} />
                {d.isFork && <span className="badge">fork</span>}
              </div>
            )}
          </div>
          <button className="btn btn-sm" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        <div className="drawer-body">
          {d.description && <p>{d.description}</p>}
          <dl className="kv">
            <dt>Stars</dt>
            <dd>{fmtCount(d.stars)}</dd>
            <dt>Contributors</dt>
            <dd>{fmtCount(d.contributors)}</dd>
            <dt>Commits</dt>
            <dd>{fmtCount(d.commits)}</dd>
            <dt>License</dt>
            <dd>{d.license && d.license !== "None" ? d.license : "—"}</dd>
            <dt>Last update</dt>
            <dd>{fmtDate(d.lastUpdate)}</dd>
            <dt>Latest release</dt>
            <dd>{d.latestRelease || "—"}</dd>
            <dt>Commit</dt>
            <dd className="mono">{shortSha(d.commitSha)}</dd>
            {d.snippetPath && (
              <>
                <dt>SPDX snippet</dt>
                <dd className="mono small">{d.snippetPath}</dd>
              </>
            )}
          </dl>

          {!isRoot && (
            <section className="stack" style={{ gap: 8 }}>
              <h3>Evidence</h3>
              <dl className="kv">
                <dt>Strongest layer</dt>
                <dd><LayerLabel layer={d.evidenceLayer} /></dd>
                <dt>All layers</dt>
                <dd>
                  {(d.layers ?? []).length
                    ? (d.layers ?? []).map((l) => `L${l} ${LAYER_NAMES[l] ?? ""}`).join(", ")
                    : "—"}
                </dd>
                <dt>Matched lines</dt>
                <dd>{fmtCount(d.matchCount)}</dd>
                <dt>Signals</dt>
                <dd><EvidenceList evidence={d.evidence} /></dd>
                <dt>Identifiers</dt>
                <dd>
                  <div className="tags">
                    {(d.identifiers ?? []).slice(0, 40).map((i) => (
                      <span key={i} className="tag">{i}</span>
                    ))}
                    {(d.identifiers ?? []).length > 40 && (
                      <span className="faint small">+{(d.identifiers ?? []).length - 40} more</span>
                    )}
                    {!(d.identifiers ?? []).length && <span className="faint">—</span>}
                  </div>
                </dd>
                <dt>Provenance</dt>
                <dd>{(d.provenance ?? []).join(", ") || "—"}</dd>
              </dl>
            </section>
          )}

          {(out.length > 0 || inc.length > 0) && (
            <section className="stack" style={{ gap: 8 }}>
              <h3>Connections</h3>
              {out.length > 0 && (
                <div>
                  <div className="small muted">Depends on</div>
                  <ul style={{ margin: 0, paddingLeft: 0, listStyle: "none" }}>
                    {out.map((e) => <EdgeLine key={e.target} edge={e} other={e.target} onSelect={onSelect} />)}
                  </ul>
                </div>
              )}
              {inc.length > 0 && (
                <div>
                  <div className="small muted">
                    Depended on by {inc.length} {inc.length === 1 ? "repo" : "repos"}
                  </div>
                  <ul style={{ margin: 0, paddingLeft: 0, listStyle: "none", maxHeight: 220, overflow: "auto" }}>
                    {[...inc]
                      .sort((a, b) => (b.confidenceScore ?? 0) - (a.confidenceScore ?? 0))
                      .slice(0, 200)
                      .map((e) => <EdgeLine key={e.source} edge={e} other={e.source} onSelect={onSelect} />)}
                  </ul>
                </div>
              )}
            </section>
          )}

          {d.snippetPath && loadSnippet && (
            <SpdxSection key={d.snippetPath} path={d.snippetPath} load={loadSnippet} />
          )}

          <section className="stack" style={{ gap: 8 }}>
            <div className="row" style={{ justifyContent: "space-between" }}>
              <h3>Papers ({(d.papers ?? []).length})</h3>
              {(d.papers ?? []).length > 0 && (
                <select style={{ width: 120, height: 28 }} value={tier} onChange={(e) => setTier(e.target.value)} aria-label="Relevance tier">
                  <option value="all">all tiers</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                </select>
              )}
            </div>
            {diag.skipped && <p className="small muted">Citation mining skipped ({diag.skipped}).</p>}
            {diag.complete === false && (
              <div className="banner warn small">
                <div>
                  Citation search for this repo was partial — a re-run may find more.
                  {diag.warnings?.length ? (
                    <ul>{diag.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
                  ) : null}
                </div>
              </div>
            )}
            {papers.map((p) => <PaperItem key={p.doi || p.title} p={p} />)}
            {!(d.papers ?? []).length && !diag.skipped && <p className="small muted">No papers found.</p>}
          </section>
        </div>
      </aside>
    </>
  );
}
