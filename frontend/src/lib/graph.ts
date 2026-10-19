// View model over a Universal Dependency Graph: indexed nodes/edges, one row
// per dependent, facet counts, filters shared by the table and the graph, the
// cross-node paper list, and CSV export.

import type {
  Confidence,
  Graph,
  GraphEdge,
  GraphNode,
  NodeData,
  Paper,
  Relationship,
} from "../api/types";

export const CONFIDENCES: Confidence[] = ["high", "medium", "low", "unknown"];
export const RELATIONSHIPS: Relationship[] = ["DEPENDS_ON", "VENDORED", "MIRROR"];

export const LAYER_NAMES: Record<number, string> = {
  1: "narrative",
  2: "source",
  3: "build manifest",
  4: "package registry",
  5: "binary / link",
  6: "SBOM / attestation",
  7: "bibliometric",
};

export const TIER_RANK: Record<string, number> = { high: 3, medium: 2, low: 1, unknown: 0 };

export interface DependentRow {
  id: string;
  label: string;
  owner: string;
  depth: number;
  confidence: Confidence;
  score: number;
  relationship: Relationship;
  layer: number | null;
  layers: number[];
  stars: number;
  contributors: number;
  commits: number;
  matchCount: number;
  license: string;
  lastUpdate: string;
  latestRelease: string;
  isFork: boolean;
  description: string;
  papersTotal: number;
  papersHigh: number;
  /** Providers this repo was found depending on (edge targets). */
  dependsOn: string[];
}

export interface AggregatedPaper {
  key: string;
  doi: string;
  title: string;
  year: number | null;
  journal: string;
  url: string;
  authors: string[];
  relation: string;
  tier: string;
  score: number | null;
  citationDepth: number | null;
  citations: number | null;
  provenance: string[];
  nodes: string[];
}

export interface GraphModel {
  graph: Graph;
  root: GraphNode | undefined;
  rootId: string;
  nodesById: Map<string, GraphNode>;
  edgesBySource: Map<string, GraphEdge[]>;
  edgesByTarget: Map<string, GraphEdge[]>;
  rows: DependentRow[];
  papers: AggregatedPaper[];
  maxDepth: number;
}

function asConfidence(v: unknown): Confidence {
  return v === "high" || v === "medium" || v === "low" ? v : "unknown";
}

function asRelationship(v: unknown): Relationship {
  return v === "VENDORED" || v === "MIRROR" ? v : "DEPENDS_ON";
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V) {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

/** Throws with a readable message when `raw` isn't a dependency graph. */
export function assertGraph(raw: unknown): asserts raw is Graph {
  if (!raw || typeof raw !== "object") throw new Error("Not a JSON object.");
  const g = raw as Record<string, unknown>;
  if (!Array.isArray(g.nodes) || !Array.isArray(g.edges)) {
    throw new Error("Not a dependency graph: expected top-level `nodes` and `edges` arrays.");
  }
}

export function buildModel(graph: Graph): GraphModel {
  const nodesById = new Map<string, GraphNode>();
  for (const n of graph.nodes) if (n.id) nodesById.set(n.id, n);

  const rootRaw = String(graph.meta?.root ?? "").replace(/^(https?:\/\/)?github\.com\//, "");
  const root =
    nodesById.get(rootRaw) ??
    graph.nodes.find((n) => n.data?.depth === 0) ??
    graph.nodes[0];
  const rootId = root?.id ?? rootRaw;

  const edgesBySource = new Map<string, GraphEdge[]>();
  const edgesByTarget = new Map<string, GraphEdge[]>();
  for (const e of graph.edges) {
    push(edgesBySource, e.source, e);
    push(edgesByTarget, e.target, e);
  }

  let maxDepth = 0;
  const rows: DependentRow[] = [];
  for (const n of graph.nodes) {
    if (!n.id || n.id === rootId) continue;
    const d: NodeData = n.data ?? {};
    const out = edgesBySource.get(n.id) ?? [];
    // Strongest edge wins when a repo depends on several providers.
    const best = out.reduce<GraphEdge | undefined>(
      (a, e) => (!a || (e.confidenceScore ?? 0) > (a.confidenceScore ?? 0) ? e : a),
      undefined,
    );
    const papers = d.papers ?? [];
    const depth = d.depth ?? 1;
    maxDepth = Math.max(maxDepth, depth);
    rows.push({
      id: n.id,
      label: n.label ?? d.packageName ?? n.id,
      owner: d.packageOwner ?? n.id.split("/")[0],
      depth,
      confidence: asConfidence(best?.confidence ?? d.confidence),
      score: Number(best?.confidenceScore ?? d.confidenceScore ?? 0),
      relationship: asRelationship(d.relationship ?? best?.relationship),
      layer: (best?.evidenceLayer ?? d.evidenceLayer ?? null) as number | null,
      layers: (best?.layers ?? d.layers ?? []) as number[],
      stars: d.stars ?? 0,
      contributors: d.contributors ?? 0,
      commits: d.commits ?? 0,
      matchCount: best?.matchCount ?? d.matchCount ?? 0,
      license: d.license ?? "None",
      lastUpdate: d.lastUpdate ?? "",
      latestRelease: d.latestRelease ?? "",
      isFork: Boolean(d.isFork),
      description: d.description ?? "",
      papersTotal: papers.length,
      papersHigh: papers.filter((p) => p.relevanceTier === "high").length,
      dependsOn: [...new Set(out.map((e) => e.target))].sort(),
    });
  }
  rows.sort((a, b) => b.score - a.score || b.stars - a.stars || a.id.localeCompare(b.id));

  return {
    graph,
    root,
    rootId,
    nodesById,
    edgesBySource,
    edgesByTarget,
    rows,
    papers: aggregatePapers(graph.nodes),
    maxDepth,
  };
}

export function paperKey(p: Paper): string {
  return (p.doi || p.url || p.title || "").toLowerCase();
}

export function aggregatePapers(nodes: GraphNode[]): AggregatedPaper[] {
  const byKey = new Map<string, AggregatedPaper>();
  for (const n of nodes) {
    for (const p of n.data?.papers ?? []) {
      const key = paperKey(p);
      if (!key) continue;
      const tier = p.relevanceTier ?? "unknown";
      const score = typeof p.relevanceScore === "number" ? p.relevanceScore : null;
      const existing = byKey.get(key);
      if (!existing) {
        byKey.set(key, {
          key,
          doi: p.doi ?? "",
          title: p.title ?? "(untitled)",
          year: p.year ?? null,
          journal: p.journal ?? "",
          url: p.url || (p.doi ? `https://doi.org/${p.doi}` : ""),
          authors: p.authors ?? [],
          relation: p.relation ?? "",
          tier,
          score,
          citationDepth: p.citationDepth ?? null,
          citations: p.citations ?? null,
          provenance: [...(p.provenance ?? [])],
          nodes: n.id ? [n.id] : [],
        });
        continue;
      }
      if (n.id && !existing.nodes.includes(n.id)) existing.nodes.push(n.id);
      for (const pr of p.provenance ?? []) {
        if (!existing.provenance.includes(pr)) existing.provenance.push(pr);
      }
      if ((TIER_RANK[tier] ?? 0) > (TIER_RANK[existing.tier] ?? 0)) existing.tier = tier;
      if (score != null && (existing.score == null || score > existing.score)) {
        existing.score = score;
      }
      if (p.relation === "seminal") existing.relation = "seminal";
    }
  }
  return [...byKey.values()].sort(
    (a, b) =>
      (TIER_RANK[b.tier] ?? 0) - (TIER_RANK[a.tier] ?? 0) ||
      (b.score ?? -1) - (a.score ?? -1) ||
      a.key.localeCompare(b.key),
  );
}

// ---------------------------------------------------------------------------
// Filters (shared by table + graph)
// ---------------------------------------------------------------------------

export interface Filters {
  text: string;
  confidence: Confidence[];
  relationship: Relationship[];
  layers: number[];
  maxDepth: number | null;
}

export const emptyFilters: Filters = {
  text: "",
  confidence: [],
  relationship: [],
  layers: [],
  maxDepth: null,
};

export function isFiltered(f: Filters): boolean {
  return Boolean(
    f.text.trim() ||
      f.confidence.length ||
      f.relationship.length ||
      f.layers.length ||
      f.maxDepth != null,
  );
}

export function applyFilters(rows: DependentRow[], f: Filters): DependentRow[] {
  const q = f.text.trim().toLowerCase();
  return rows.filter(
    (r) =>
      (!q ||
        r.id.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q) ||
        r.license.toLowerCase().includes(q)) &&
      (!f.confidence.length || f.confidence.includes(r.confidence)) &&
      (!f.relationship.length || f.relationship.includes(r.relationship)) &&
      (!f.layers.length || (r.layer != null && f.layers.includes(r.layer))) &&
      (f.maxDepth == null || r.depth <= f.maxDepth),
  );
}

export function facetCounts(rows: DependentRow[]) {
  const confidence: Record<string, number> = {};
  const relationship: Record<string, number> = {};
  const layer: Record<string, number> = {};
  for (const r of rows) {
    confidence[r.confidence] = (confidence[r.confidence] ?? 0) + 1;
    relationship[r.relationship] = (relationship[r.relationship] ?? 0) + 1;
    if (r.layer != null) layer[r.layer] = (layer[r.layer] ?? 0) + 1;
  }
  return { confidence, relationship, layer };
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

function csvCell(v: unknown): string {
  const s = Array.isArray(v) ? v.join(" ") : v == null ? "" : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function rowsToCsv(rows: DependentRow[]): string {
  const cols: (keyof DependentRow)[] = [
    "id",
    "depth",
    "confidence",
    "score",
    "relationship",
    "layer",
    "stars",
    "contributors",
    "commits",
    "matchCount",
    "license",
    "lastUpdate",
    "latestRelease",
    "isFork",
    "papersTotal",
    "papersHigh",
    "dependsOn",
    "description",
  ];
  const lines = [cols.join(",")];
  for (const r of rows) lines.push(cols.map((c) => csvCell(r[c])).join(","));
  return lines.join("\n") + "\n";
}

export function downloadBlob(filename: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function slug(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]+/g, "_");
}
