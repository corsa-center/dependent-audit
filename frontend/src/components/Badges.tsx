import type { JobStatus } from "../api/types";
import { LAYER_NAMES } from "../lib/graph";

export function ConfidenceBadge({ value, score }: { value: string | null | undefined; score?: number }) {
  const v = value ?? "unknown";
  return (
    <span className={`badge conf-${v}`} title={score != null ? `score ${score.toFixed(2)}` : undefined}>
      <span className="dot" style={{ background: `var(--conf-${v})` }} />
      {v}
    </span>
  );
}

const REL_LABEL: Record<string, string> = {
  DEPENDS_ON: "depends on",
  VENDORED: "vendored copy",
  MIRROR: "mirror / fork",
};

export function RelationshipBadge({ value }: { value: string | null | undefined }) {
  const v = value ?? "DEPENDS_ON";
  return <span className={`badge rel-${v}`}>{REL_LABEL[v] ?? v}</span>;
}

export function LayerLabel({ layer }: { layer: number | null | undefined }) {
  if (layer == null) return <span className="faint">—</span>;
  return (
    <span title={`Evidence layer ${layer}`}>
      <span className="mono faint">L{layer}</span> {LAYER_NAMES[layer] ?? ""}
    </span>
  );
}

export function StatusBadge({ status }: { status: JobStatus | string | null | undefined }) {
  const s = status ?? "queued";
  return (
    <span className={`badge st-${s}`}>
      {s === "running" && <span className="dot pulse" style={{ background: "currentColor" }} />}
      {s}
    </span>
  );
}

export function PaperTierBadge({ tier }: { tier: string | null | undefined }) {
  const t = tier ?? "unknown";
  return <span className={`badge conf-${t === "unknown" ? "unknown" : t}`}>{t}</span>;
}
