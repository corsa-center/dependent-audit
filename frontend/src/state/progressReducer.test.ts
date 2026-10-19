import { describe, expect, it } from "vitest";
import type { StreamedEvent } from "../api/events";
import { applyEvents, initialProgress, sortedRows } from "./progressReducer";

let seq = 0;
function ev<T extends StreamedEvent["type"]>(
  type: T,
  data: Extract<StreamedEvent, { type: T }>["data"],
  src: "web" | "worker" | "crawler" = "crawler",
): StreamedEvent {
  const id = seq++;
  return { id, seq: id, ts: 1000 + id, type, src, data } as StreamedEvent;
}

function run(events: StreamedEvent[]) {
  return applyEvents(initialProgress, events);
}

describe("applyEvents", () => {
  it("tracks lifecycle, phases, candidates, enrichment and result", () => {
    seq = 0;
    const s = run([
      ev("job", { status: "queued" }, "web"),
      ev("job", { status: "running", startedAt: 1001 }, "worker"),
      ev("run_started", {
        runId: "r", root: "LLNL/zfp", name: "zfp", depth: 1, ecosystem: "cpp",
        citations: true, sgCount: "5000", eventsVersion: 1,
      }),
      ev("phase", { phase: "search", state: "start", repo: "LLNL/zfp" }),
      ev("search_progress", { repo: "LLNL/zfp", matches: 10, lines: 12, consumers: 2, elapsedSec: 1, final: false }),
      ev("phase", { phase: "search", state: "end", repo: "LLNL/zfp", detail: { matches: 10 } }),
      ev("candidates", {
        parent: "LLNL/zfp", depth: 1, total: 2, batchIndex: 0, batchCount: 1,
        batch: [
          { id: "a/low", confidence: "low", confidenceScore: 1, relationship: "DEPENDS_ON", evidenceLayer: 2, matchCount: 1 },
          { id: "b/high", confidence: "high", confidenceScore: 9, relationship: "DEPENDS_ON", evidenceLayer: 4, matchCount: 7 },
        ],
      }),
      ev("enrich_progress", { parent: "LLNL/zfp", done: 1, total: 2, repo: "b/high" }),
      ev("node", { id: "b/high", label: "high", type: "consumer", depth: 1, stars: 50, papers: { total: 0, seminal: 0 } }),
      ev("edge", {
        source: "b/high", target: "LLNL/zfp", relationship: "MIRROR", confidence: "high",
        confidenceScore: 9, evidenceLayer: 4, layers: [2, 4], matchCount: 7, evidence: {},
        identifiers: [], identifiersTotal: 0,
      }),
      ev("log", { level: "WARNING", message: "careful" }),
      ev("result", { complete: true, warnings: [], nodes: 3, edges: 1, elapsedSec: 5, completeness: { complete: true, warnings: [] } }),
      ev("job", { status: "succeeded", returncode: 0 }, "worker"),
    ]);
    expect(s.status).toBe("succeeded");
    expect(s.root).toBe("LLNL/zfp");
    expect(s.phases).toHaveLength(1);
    expect(s.phases[0]).toMatchObject({ phase: "search", state: "done", detail: { matches: 10 } });
    expect(s.search?.matches).toBe(10);
    const rows = sortedRows(s);
    expect(rows.map((r) => r.id)).toEqual(["b/high", "a/low"]);
    expect(rows[0].enriched).toBe(true);
    expect(rows[0].node?.stars).toBe(50);
    expect(rows[0].relationship).toBe("MIRROR"); // upgraded by the edge
    expect(rows[1].enriched).toBe(false);
    expect(s.logs[0].message).toBe("careful");
    expect(s.result?.complete).toBe(true);
    expect(s.finishedAt).not.toBeNull();
  });

  it("ignores duplicate ids replayed after a reconnect", () => {
    seq = 0;
    const first = [ev("job", { status: "queued" }, "web"), ev("log", { level: "WARNING", message: "x" })];
    const s1 = applyEvents(initialProgress, first);
    const s2 = applyEvents(s1, first);
    expect(s2.logs).toHaveLength(1);
    expect(s2.lastId).toBe(1);
  });

  it("does not mutate the previous state", () => {
    seq = 0;
    const s1 = run([ev("phase", { phase: "enrich", state: "start", repo: "r" })]);
    const snapshot = JSON.stringify(s1);
    applyEvents(s1, [ev("phase", { phase: "enrich", state: "end", repo: "r" }), ev("job", { status: "failed" }, "worker")]);
    expect(JSON.stringify(s1)).toBe(snapshot);
  });

  it("closes running phases when the job ends", () => {
    seq = 0;
    const s = run([
      ev("phase", { phase: "search", state: "start", repo: "r" }),
      ev("job", { status: "cancelled", error: "cancelled by request" }, "worker"),
    ]);
    expect(s.phases[0].state).toBe("done");
    expect(s.error).toBe("cancelled by request");
  });
});
