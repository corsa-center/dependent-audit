// Folds the job's progress-event stream into the live view model. Pure and
// batch-oriented: `applyEvents` copies the containers once per batch (a replay
// can be thousands of events) and then mutates the copies.

import type {
  CandidateRow,
  Completeness,
  EdgeSummary,
  NodeSummary,
  PhaseName,
  StreamedEvent,
} from "../api/events";
import type { Confidence, JobStatus, Relationship } from "../api/types";

export interface PhaseEntry {
  phase: PhaseName;
  repo: string;
  state: "running" | "done";
  startTs: number;
  endTs?: number;
  detail?: Record<string, unknown>;
}

export interface SearchCounter {
  repo: string;
  matches: number;
  consumers: number;
  elapsedSec: number;
  final: boolean;
}

export interface LiveRow {
  id: string;
  parent: string;
  depth: number;
  confidence: Confidence | null;
  confidenceScore: number;
  relationship: Relationship;
  evidenceLayer: number | null;
  matchCount: number;
  /** Filled once the node's metadata has been fetched (a `node` event). */
  node?: NodeSummary;
  enriched: boolean;
}

export interface LogEntry {
  ts: number;
  level: string;
  message: string;
  repo?: string | null;
}

export interface ProgressState {
  lastId: number;
  status: JobStatus | null;
  error: string | null;
  startedAt: number | null;
  finishedAt: number | null;
  root: string | null;
  depth: number | null;
  citations: boolean | null;
  phases: PhaseEntry[];
  current: { repo: string; depth: number; processed: number; queued: number } | null;
  search: SearchCounter | null;
  enrich: { parent: string; done: number; total: number; repo: string } | null;
  rows: Record<string, LiveRow>;
  rootNode: NodeSummary | null;
  edges: EdgeSummary[];
  logs: LogEntry[];
  incomplete: { scope: string; repo?: string; reason: string }[];
  result: {
    complete: boolean;
    warnings: string[];
    nodes: number;
    edges: number;
    elapsedSec: number;
    completeness: Completeness;
  } | null;
  crawlerError: { message: string; excType: string } | null;
}

export const initialProgress: ProgressState = {
  lastId: -1,
  status: null,
  error: null,
  startedAt: null,
  finishedAt: null,
  root: null,
  depth: null,
  citations: null,
  phases: [],
  current: null,
  search: null,
  enrich: null,
  rows: {},
  rootNode: null,
  edges: [],
  logs: [],
  incomplete: [],
  result: null,
  crawlerError: null,
};

const MAX_LOGS = 500;

function candidateRow(c: CandidateRow, parent: string, depth: number): LiveRow {
  return {
    id: c.id,
    parent,
    depth,
    confidence: c.confidence,
    confidenceScore: c.confidenceScore ?? 0,
    relationship: c.relationship ?? "DEPENDS_ON",
    evidenceLayer: c.evidenceLayer ?? null,
    matchCount: c.matchCount ?? 0,
    enriched: false,
  };
}

export function applyEvents(
  prev: ProgressState,
  events: readonly StreamedEvent[],
): ProgressState {
  if (events.length === 0) return prev;
  const s: ProgressState = {
    ...prev,
    phases: prev.phases.slice(),
    rows: { ...prev.rows },
    edges: prev.edges.slice(),
    logs: prev.logs.slice(),
    incomplete: prev.incomplete.slice(),
  };

  for (const ev of events) {
    if (ev.id <= s.lastId) continue; // duplicate after a reconnect
    s.lastId = ev.id;
    switch (ev.type) {
      case "job": {
        s.status = ev.data.status;
        if (ev.data.status === "running") s.startedAt = ev.data.startedAt ?? ev.ts;
        if (ev.data.error) s.error = ev.data.error;
        if (ev.data.status !== "queued" && ev.data.status !== "running") {
          s.finishedAt = ev.ts;
          s.phases = s.phases.map((p) =>
            p.state === "running" ? { ...p, state: "done", endTs: ev.ts } : p,
          );
        }
        break;
      }
      case "run_started":
        s.root = ev.data.root;
        s.depth = ev.data.depth;
        s.citations = ev.data.citations;
        break;
      case "phase": {
        const { phase, state, repo, detail } = ev.data;
        if (state === "start") {
          s.phases.push({ phase, repo, state: "running", startTs: ev.ts });
        } else {
          for (let i = s.phases.length - 1; i >= 0; i--) {
            const p = s.phases[i];
            if (p.phase === phase && p.repo === repo && p.state === "running") {
              s.phases[i] = { ...p, state: "done", endTs: ev.ts, detail };
              break;
            }
          }
        }
        break;
      }
      case "node_start":
        s.current = {
          repo: ev.data.repo,
          depth: ev.data.depth,
          processed: ev.data.processed,
          queued: ev.data.queued,
        };
        s.search = null;
        s.enrich = null;
        break;
      case "search_progress":
        s.search = {
          repo: ev.data.repo,
          matches: ev.data.matches,
          consumers: ev.data.consumers,
          elapsedSec: ev.data.elapsedSec,
          final: ev.data.final,
        };
        break;
      case "candidates":
        for (const c of ev.data.batch) {
          const existing = s.rows[c.id];
          // A repo reached from several parents keeps its strongest edge.
          if (!existing || (c.confidenceScore ?? 0) > existing.confidenceScore) {
            s.rows[c.id] = {
              ...candidateRow(c, ev.data.parent, ev.data.depth),
              node: existing?.node,
              enriched: existing?.enriched ?? false,
            };
          }
        }
        break;
      case "enrich_progress":
        s.enrich = { ...ev.data };
        break;
      case "node": {
        if (ev.data.depth === 0 || ev.data.type === "library") {
          s.rootNode = ev.data;
        } else {
          const row = s.rows[ev.data.id];
          s.rows[ev.data.id] = row
            ? { ...row, node: ev.data, enriched: true }
            : {
                id: ev.data.id,
                parent: "",
                depth: ev.data.depth,
                confidence: ev.data.confidence ?? null,
                confidenceScore: ev.data.confidenceScore ?? 0,
                relationship: ev.data.relationship ?? "DEPENDS_ON",
                evidenceLayer: ev.data.evidenceLayer ?? null,
                matchCount: ev.data.matchCount ?? 0,
                node: ev.data,
                enriched: true,
              };
        }
        break;
      }
      case "edge": {
        s.edges.push(ev.data);
        const row = s.rows[ev.data.source];
        if (row && ev.data.relationship !== row.relationship) {
          // e.g. the fork check upgrades DEPENDS_ON -> MIRROR at enrichment.
          s.rows[ev.data.source] = { ...row, relationship: ev.data.relationship };
        }
        break;
      }
      case "incomplete":
        s.incomplete.push(ev.data);
        break;
      case "log":
        s.logs.push({
          ts: ev.ts,
          level: ev.data.level,
          message: ev.data.message,
          repo: ev.data.repo,
        });
        if (s.logs.length > MAX_LOGS) s.logs.splice(0, s.logs.length - MAX_LOGS);
        break;
      case "result":
        s.result = ev.data;
        break;
      case "error":
        s.crawlerError = ev.data;
        break;
    }
  }
  return s;
}

/** Live rows, strongest first (score, then id), for the in-progress table. */
export function sortedRows(state: ProgressState): LiveRow[] {
  return Object.values(state.rows).sort(
    (a, b) => b.confidenceScore - a.confidenceScore || a.id.localeCompare(b.id),
  );
}
