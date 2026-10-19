import { describe, expect, it } from "vitest";
import type { Graph } from "../api/types";
import { applyFilters, assertGraph, buildModel, emptyFilters, facetCounts, rowsToCsv } from "./graph";

const graph: Graph = {
  meta: { root: "LLNL/zfp", schemaVersion: "2.3" },
  nodes: [
    {
      id: "LLNL/zfp", label: "zfp", type: "library",
      data: {
        depth: 0, stars: 800,
        papers: [
          { doi: "10.1/seminal", title: "ZFP", relation: "seminal", relevanceTier: "high", relevanceScore: 9, provenance: ["seminal"] },
          { doi: "10.1/shared", title: "Shared", relation: "citing", relevanceTier: "medium", relevanceScore: 4, provenance: ["reverse_citation"] },
        ],
      },
    },
    {
      id: "a/app", label: "app", type: "consumer",
      data: {
        depth: 1, stars: 10, confidence: "high", confidenceScore: 9, relationship: "DEPENDS_ON",
        description: "Uses zfp, \"quoted\"", license: "MIT",
        papers: [{ doi: "10.1/SHARED", title: "Shared", relation: "citing", relevanceTier: "high", relevanceScore: 6, provenance: ["text_scrape"] }],
      },
    },
    { id: "b/vend", label: "vend", type: "consumer", data: { depth: 1, stars: 3, confidence: "low", confidenceScore: 1, relationship: "VENDORED" } },
    { id: "c/deep", label: "deep", type: "consumer", data: { depth: 2, stars: 0, confidence: "medium", confidenceScore: 4 } },
  ],
  edges: [
    { source: "a/app", target: "LLNL/zfp", confidence: "high", confidenceScore: 9, evidenceLayer: 4, layers: [2, 4], matchCount: 5 },
    { source: "b/vend", target: "LLNL/zfp", confidence: "low", confidenceScore: 1, evidenceLayer: 2, relationship: "VENDORED" },
    { source: "c/deep", target: "a/app", confidence: "medium", confidenceScore: 4, evidenceLayer: 3 },
  ],
};

describe("buildModel", () => {
  const model = buildModel(graph);

  it("finds the root and one row per dependent, strongest first", () => {
    expect(model.rootId).toBe("LLNL/zfp");
    expect(model.rows.map((r) => r.id)).toEqual(["a/app", "c/deep", "b/vend"]);
    expect(model.maxDepth).toBe(2);
    const app = model.rows[0];
    expect(app).toMatchObject({ confidence: "high", layer: 4, matchCount: 5, papersTotal: 1, papersHigh: 1 });
    expect(model.rows[2].relationship).toBe("VENDORED");
    expect(model.edgesByTarget.get("LLNL/zfp")).toHaveLength(2);
  });

  it("dedupes papers by DOI (case-insensitive) and keeps the best tier", () => {
    expect(model.papers).toHaveLength(2);
    const shared = model.papers.find((p) => p.key === "10.1/shared")!;
    expect(shared.tier).toBe("high");
    expect(shared.score).toBe(6);
    expect(shared.nodes.sort()).toEqual(["LLNL/zfp", "a/app"]);
    expect(shared.provenance.sort()).toEqual(["reverse_citation", "text_scrape"]);
  });

  it("filters and counts facets", () => {
    expect(applyFilters(model.rows, { ...emptyFilters, confidence: ["low"] }).map((r) => r.id)).toEqual(["b/vend"]);
    expect(applyFilters(model.rows, { ...emptyFilters, maxDepth: 1 })).toHaveLength(2);
    expect(applyFilters(model.rows, { ...emptyFilters, text: "MIT" }).map((r) => r.id)).toEqual(["a/app"]);
    expect(applyFilters(model.rows, { ...emptyFilters, layers: [3] }).map((r) => r.id)).toEqual(["c/deep"]);
    expect(facetCounts(model.rows).relationship).toEqual({ DEPENDS_ON: 2, VENDORED: 1 });
  });

  it("exports CSV with quoting", () => {
    const csv = rowsToCsv(model.rows);
    const lines = csv.trim().split("\n");
    expect(lines[0].startsWith("id,depth,confidence")).toBe(true);
    expect(lines).toHaveLength(4);
    expect(csv).toContain('"Uses zfp, ""quoted"""');
  });
});

describe("assertGraph", () => {
  it("rejects non-graphs", () => {
    expect(() => assertGraph({ foo: 1 })).toThrow(/nodes/);
    expect(() => assertGraph(null)).toThrow();
    expect(() => assertGraph(graph)).not.toThrow();
  });
});
