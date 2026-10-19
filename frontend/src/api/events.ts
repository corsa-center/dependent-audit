// Progress events streamed from GET /api/jobs/<id>/events (one JSON object per
// SSE message; the SSE id is the event's line index). Mirrors the catalogue in
// deploy/README.md — keep them in sync. eventsVersion: 1.

import type { Confidence, JobStatus, Relationship } from "./types";

interface Envelope<T extends string, D> {
  seq: number;
  ts: number;
  type: T;
  src: "web" | "worker" | "crawler";
  data: D;
}

export interface CandidateRow {
  id: string;
  confidence: Confidence | null;
  confidenceScore: number;
  relationship: Relationship;
  evidenceLayer: number | null;
  matchCount: number;
}

export interface NodeSummary {
  id: string;
  label: string;
  type: string;
  depth: number;
  stars: number;
  contributors?: number;
  license?: string | null;
  isFork?: boolean;
  lastUpdate?: string | null;
  latestRelease?: string | null;
  description?: string;
  confidence?: Confidence | null;
  confidenceScore?: number;
  relationship?: Relationship | null;
  evidenceLayer?: number | null;
  matchCount?: number;
  snippetPath?: string | null;
  papers: { total: number; seminal: number; high?: number; medium?: number; low?: number };
  papersComplete?: boolean;
}

export interface EdgeSummary {
  source: string;
  target: string;
  relationship: Relationship;
  confidence: Confidence | null;
  confidenceScore: number;
  evidenceLayer: number | null;
  layers: number[];
  matchCount: number;
  evidence: Record<string, number>;
  identifiers: string[];
  identifiersTotal: number;
}

export interface Completeness {
  complete: boolean;
  warnings: string[];
  [k: string]: unknown;
}

export type PhaseName =
  | "root_metadata"
  | "declared"
  | "identifiers"
  | "specificity"
  | "search"
  | "scoring"
  | "enrich"
  | "write";

export type JobEvent = Envelope<
  "job",
  {
    status: JobStatus;
    jobId?: string;
    repo?: string;
    name?: string;
    depth?: number;
    startedAt?: number;
    returncode?: number | null;
    error?: string | null;
    elapsedSec?: number | null;
  }
>;

export type AuditEvent =
  | JobEvent
  | Envelope<
      "run_started",
      {
        runId: string;
        root: string;
        name: string;
        depth: number;
        ecosystem: string;
        citations: boolean;
        sgCount: string;
        eventsVersion: number;
      }
    >
  | Envelope<
      "phase",
      {
        phase: PhaseName;
        state: "start" | "end";
        repo: string;
        depth?: number;
        detail?: Record<string, unknown>;
      }
    >
  | Envelope<
      "node_start",
      { repo: string; depth: number; chain: string[]; processed: number; queued: number }
    >
  | Envelope<
      "search_progress",
      {
        repo: string;
        matches: number;
        lines: number;
        consumers: number;
        elapsedSec: number;
        final: boolean;
      }
    >
  | Envelope<
      "candidates",
      {
        parent: string;
        depth: number;
        total: number;
        batchIndex: number;
        batchCount: number;
        batch: CandidateRow[];
      }
    >
  | Envelope<"enrich_progress", { parent: string; done: number; total: number; repo: string }>
  | Envelope<"node", NodeSummary>
  | Envelope<"edge", EdgeSummary>
  | Envelope<"incomplete", { scope: "discovery" | "citations"; repo?: string; reason: string }>
  | Envelope<
      "log",
      {
        level: string;
        message: string;
        repo?: string | null;
        depth?: number | null;
        extra?: Record<string, unknown> | null;
      }
    >
  | Envelope<
      "result",
      {
        complete: boolean;
        warnings: string[];
        nodes: number;
        edges: number;
        elapsedSec: number;
        completeness: Completeness;
      }
    >
  | Envelope<"error", { message: string; excType: string }>;

/** An event plus the SSE id (line index) it arrived with. */
export type StreamedEvent = AuditEvent & { id: number };
