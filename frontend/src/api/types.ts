import type { UniversalDependencyGraph } from "./udg.generated";

export type Graph = UniversalDependencyGraph;
export type GraphNode = Graph["nodes"][number];
export type NodeData = NonNullable<GraphNode["data"]>;
export type GraphEdge = Graph["edges"][number];
export type Paper = NonNullable<NodeData["papers"]>[number];

export type Confidence = "high" | "medium" | "low" | "unknown";
export type Relationship = "DEPENDS_ON" | "VENDORED" | "MIRROR";

export type JobStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "timeout"
  | "cancelled";

export const TERMINAL: ReadonlySet<string> = new Set([
  "succeeded",
  "failed",
  "timeout",
  "cancelled",
]);

export interface JobLinks {
  self: string;
  events: string;
  graph: string;
  spdx: string;
  log: string;
}

export interface JobMeta {
  id: string;
  status: JobStatus;
  repo: string | null;
  name?: string | null;
  depth: number | null;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
  error: string | null;
  returncode: number | null;
  links?: JobLinks;
  params?: Record<string, unknown>;
  hasGraph?: boolean;
  hasSpdx?: boolean;
  lastEvent?: { type: string; ts: number; data: Record<string, unknown> } | null;
}

export type OptionKind = "str" | "int" | "float" | "flag" | "choice";

export interface OptionSpec {
  key: string;
  flag: string;
  kind: OptionKind;
  group: "basic" | "discovery" | "citations" | "advanced";
  help?: string;
  default?: string | number | boolean;
  choices?: string[];
  min?: number;
  required?: boolean;
}

export interface Health {
  status: "ok" | "degraded";
  worker: {
    alive: boolean;
    lastSeen: number | null;
    concurrency: number | null;
    inflight: number | null;
    sgToken: boolean;
    ghToken: boolean;
    auditTimeout: number | null;
  };
}
