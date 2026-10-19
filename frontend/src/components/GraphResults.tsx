import { lazy, Suspense, useCallback, useMemo, useState } from "react";
import type { Graph } from "../api/types";
import { fmtCount, githubUrl } from "../lib/format";
import {
  applyFilters,
  buildModel,
  CONFIDENCES,
  downloadBlob,
  emptyFilters,
  facetCounts,
  rowsToCsv,
  slug,
  type Filters,
} from "../lib/graph";
import { DependentsTable } from "./DependentsTable";
import { FilterBar } from "./FilterBar";
import { NodeDrawer, type SnippetLoader } from "./NodeDrawer";
import { PapersTable } from "./PapersTable";

const GraphView = lazy(() => import("./GraphView"));

type Tab = "table" | "graph" | "papers";

interface Props {
  graph: Graph;
  /** Server download URLs (job results). Omitted in the standalone viewer. */
  graphHref?: string;
  spdxHref?: string;
  sourceLabel?: string;
  /** Resolves a node's SPDX snippet (server route, or an uploaded zip). */
  loadSnippet?: SnippetLoader;
}

export function GraphResults({ graph, graphHref, spdxHref, sourceLabel, loadSnippet }: Props) {
  const model = useMemo(() => buildModel(graph), [graph]);
  const [tab, setTab] = useState<Tab>("table");
  const [filters, setFilters] = useState<Filters>(emptyFilters);
  const [selected, setSelected] = useState<string | null>(null);

  const rows = useMemo(() => applyFilters(model.rows, filters), [model, filters]);
  const counts = useMemo(() => facetCounts(model.rows), [model]);
  const close = useCallback(() => setSelected(null), []);

  const completeness = graph.meta?.completeness;
  const root = model.root;
  const rootData = root?.data ?? {};
  const base = slug(String(graph.meta?.root ?? model.rootId ?? "graph"));
  const totalPapers = model.papers.length;
  const confTotal = model.rows.length || 1;

  return (
    <div className="stack">
      <div className="card card-pad stack" style={{ gap: 12 }}>
        <div className="row" style={{ justifyContent: "space-between", alignItems: "flex-start" }}>
          <div className="head-main">
            <div className="small muted">
              {sourceLabel ? `${sourceLabel} · ` : ""}schema {String(graph.meta?.schemaVersion ?? "?")}
              {graph.meta?.ecosystem ? ` · ${String(graph.meta.ecosystem)}` : ""}
              {graph.meta?.fake ? " · fake data" : ""}
            </div>
            <h2 style={{ fontSize: 18 }}>
              <a href={githubUrl(model.rootId)} target="_blank" rel="noreferrer">
                {model.rootId}
              </a>
            </h2>
            {rootData.description && <p className="muted small">{rootData.description}</p>}
          </div>
          <div className="row">
            {graphHref ? (
              <a className="btn" href={graphHref} download>
                Graph JSON
              </a>
            ) : (
              <button
                className="btn"
                onClick={() =>
                  downloadBlob(`${base}_dependency_graph.json`, JSON.stringify(graph, null, 2), "application/json")
                }
              >
                Graph JSON
              </button>
            )}
            {spdxHref && (
              <a className="btn" href={spdxHref} download>
                SPDX zip
              </a>
            )}
            <button
              className="btn"
              title="Export the currently filtered dependents"
              onClick={() => downloadBlob(`${base}_dependents.csv`, rowsToCsv(rows), "text/csv")}
            >
              CSV
            </button>
          </div>
        </div>

        {completeness && completeness.complete === false && (
          <div className="banner warn">
            <div>
              <strong>Incomplete search.</strong> Some sources failed or hit a cap, so a re-run may
              find more.
              {(completeness.warnings ?? []).length > 0 && (
                <ul>
                  {(completeness.warnings ?? []).slice(0, 12).map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                  {(completeness.warnings ?? []).length > 12 && (
                    <li>…and {(completeness.warnings ?? []).length - 12} more</li>
                  )}
                </ul>
              )}
            </div>
          </div>
        )}

        <div className="stats">
          <div className="stat">
            <div className="label">Dependents</div>
            <div className="value">{fmtCount(model.rows.length)}</div>
            <div className="hint">max depth {model.maxDepth}</div>
          </div>
          <div className="stat">
            <div className="label">Confidence</div>
            <div className="stacked" style={{ margin: "10px 0 6px" }} aria-hidden>
              {CONFIDENCES.map((c) =>
                counts.confidence[c] ? (
                  <span
                    key={c}
                    style={{ width: `${(100 * counts.confidence[c]) / confTotal}%`, background: `var(--conf-${c})` }}
                  />
                ) : null,
              )}
            </div>
            <div className="hint">
              {CONFIDENCES.filter((c) => counts.confidence[c])
                .map((c) => `${counts.confidence[c]} ${c}`)
                .join(" · ") || "—"}
            </div>
          </div>
          <div className="stat">
            <div className="label">Relationships</div>
            <div className="value" style={{ fontSize: 15, marginTop: 6 }}>
              {fmtCount(counts.relationship.DEPENDS_ON ?? 0)} depends
            </div>
            <div className="hint">
              {counts.relationship.VENDORED ?? 0} vendored · {counts.relationship.MIRROR ?? 0}{" "}
              {counts.relationship.MIRROR === 1 ? "mirror" : "mirrors"}
            </div>
          </div>
          <div className="stat">
            <div className="label">Papers</div>
            <div className="value">{fmtCount(totalPapers)}</div>
            <div className="hint">{(rootData.papers ?? []).length} on the root</div>
          </div>
          <div className="stat">
            <div className="label">Root stars</div>
            <div className="value">{fmtCount(rootData.stars)}</div>
            <div className="hint">{rootData.license && rootData.license !== "None" ? rootData.license : "no license info"}</div>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="tabs" role="tablist">
          {(
            [
              ["table", "Dependents", model.rows.length],
              ["graph", "Graph", null],
              ["papers", "Papers", totalPapers],
            ] as const
          ).map(([key, label, n]) => (
            <button
              key={key}
              role="tab"
              aria-selected={tab === key}
              className={tab === key ? "active" : ""}
              onClick={() => setTab(key)}
            >
              {label}
              {n != null && <span className="count">{fmtCount(n)}</span>}
            </button>
          ))}
          <span className="grow" />
          <button className="btn btn-sm btn-ghost" style={{ alignSelf: "center" }} onClick={() => setSelected(model.rootId)}>
            Root details
          </button>
        </div>

        {tab !== "papers" && (
          <FilterBar
            filters={filters}
            onChange={setFilters}
            counts={counts}
            maxDepth={model.maxDepth}
            shown={rows.length}
            total={model.rows.length}
          />
        )}

        {tab === "table" && (
          <DependentsTable
            rows={rows}
            selectedId={selected}
            onSelect={setSelected}
            showDepth={model.maxDepth > 1}
          />
        )}
        {tab === "graph" && (
          <Suspense fallback={<div className="empty">Loading graph…</div>}>
            <GraphView model={model} rows={rows} selectedId={selected} onSelect={setSelected} />
          </Suspense>
        )}
        {tab === "papers" && <PapersTable papers={model.papers} onSelectNode={setSelected} />}
      </div>

      {selected && (
        <NodeDrawer
          model={model}
          id={selected}
          onClose={close}
          onSelect={setSelected}
          loadSnippet={loadSnippet}
        />
      )}
    </div>
  );
}
