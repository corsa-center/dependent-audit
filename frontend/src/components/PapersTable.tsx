import { useMemo, useState } from "react";
import { fmtCount, fmtScore } from "../lib/format";
import type { AggregatedPaper } from "../lib/graph";
import { PaperTierBadge } from "./Badges";

interface Props {
  papers: AggregatedPaper[];
  onSelectNode: (id: string) => void;
}

const TIERS = ["high", "medium", "low"] as const;

export function PapersTable({ papers, onSelectNode }: Props) {
  const [tiers, setTiers] = useState<string[]>([]);
  const [relation, setRelation] = useState<"all" | "seminal" | "citing">("all");
  const [q, setQ] = useState("");

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const p of papers) c[p.tier] = (c[p.tier] ?? 0) + 1;
    return c;
  }, [papers]);

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return papers.filter(
      (p) =>
        (!tiers.length || tiers.includes(p.tier)) &&
        (relation === "all" || p.relation === relation) &&
        (!needle ||
          p.title.toLowerCase().includes(needle) ||
          p.doi.toLowerCase().includes(needle) ||
          p.authors.some((a) => a.toLowerCase().includes(needle))),
    );
  }, [papers, tiers, relation, q]);

  if (!papers.length) {
    return <div className="empty">No papers in this graph (citation mining may have been skipped).</div>;
  }

  return (
    <>
      <div className="filterbar">
        <input
          type="search"
          className="search"
          placeholder="Filter titles, DOIs, authors…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          aria-label="Filter papers"
        />
        <div className="filter-group">
          <span className="lbl">Relevance</span>
          {TIERS.filter((t) => counts[t]).map((t) => (
            <button
              key={t}
              type="button"
              className={`chip ${tiers.includes(t) ? "on" : ""}`}
              aria-pressed={tiers.includes(t)}
              onClick={() => setTiers(tiers.includes(t) ? tiers.filter((x) => x !== t) : [...tiers, t])}
            >
              {t} <span className="count">{counts[t]}</span>
            </button>
          ))}
        </div>
        <div className="filter-group">
          <span className="lbl">Relation</span>
          {(["all", "seminal", "citing"] as const).map((r) => (
            <button
              key={r}
              type="button"
              className={`chip ${relation === r ? "on" : ""}`}
              aria-pressed={relation === r}
              onClick={() => setRelation(r)}
            >
              {r}
            </button>
          ))}
        </div>
        <span className="grow" />
        <span className="small muted">
          {shown.length === papers.length ? `${papers.length} papers` : `${shown.length} of ${papers.length} papers`}
        </span>
      </div>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr>
              <th>Title</th>
              <th>Year</th>
              <th>Relevance</th>
              <th>Relation</th>
              <th>Found via</th>
              <th className="num">Cited by</th>
              <th>Attached to</th>
            </tr>
          </thead>
          <tbody>
            {shown.slice(0, 1000).map((p) => (
              <tr key={p.key} style={{ cursor: "default" }}>
                <td style={{ minWidth: 280 }}>
                  {p.url ? (
                    <a href={p.url} target="_blank" rel="noreferrer" className="repo">
                      {p.title}
                    </a>
                  ) : (
                    <span className="repo">{p.title}</span>
                  )}
                  <div className="desc truncate">
                    {p.authors.slice(0, 3).join(", ")}
                    {p.authors.length > 3 ? " et al." : ""}
                    {p.journal ? ` · ${p.journal}` : ""}
                  </div>
                </td>
                <td className="nowrap">{p.year ?? "—"}</td>
                <td className="nowrap">
                  <PaperTierBadge tier={p.tier} />{" "}
                  <span className="faint small mono">{fmtScore(p.score)}</span>
                </td>
                <td className="nowrap small">
                  {p.relation === "seminal" ? "seminal" : `citing${p.citationDepth ? ` · hop ${p.citationDepth}` : ""}`}
                </td>
                <td>
                  <div className="tags">
                    {p.provenance.map((pr) => (
                      <span key={pr} className="tag">{pr}</span>
                    ))}
                  </div>
                </td>
                <td className="num">{fmtCount(p.citations)}</td>
                <td className="small">
                  {p.nodes.slice(0, 3).map((n, i) => (
                    <span key={n}>
                      {i > 0 && ", "}
                      <a href="#" onClick={(e) => { e.preventDefault(); onSelectNode(n); }}>
                        {n}
                      </a>
                    </span>
                  ))}
                  {p.nodes.length > 3 && <span className="faint"> +{p.nodes.length - 3}</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {shown.length > 1000 && (
          <div className="empty small">Showing the first 1000 — narrow the filters to see more.</div>
        )}
      </div>
    </>
  );
}
