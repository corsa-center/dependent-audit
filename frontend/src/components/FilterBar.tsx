import type { Confidence, Relationship } from "../api/types";
import {
  CONFIDENCES,
  LAYER_NAMES,
  RELATIONSHIPS,
  emptyFilters,
  isFiltered,
  type Filters,
} from "../lib/graph";

interface Props {
  filters: Filters;
  onChange: (f: Filters) => void;
  counts: {
    confidence: Record<string, number>;
    relationship: Record<string, number>;
    layer: Record<string, number>;
  };
  maxDepth: number;
  shown: number;
  total: number;
}

function toggle<T>(list: T[], v: T): T[] {
  return list.includes(v) ? list.filter((x) => x !== v) : [...list, v];
}

const REL_SHORT: Record<Relationship, string> = {
  DEPENDS_ON: "depends",
  VENDORED: "vendored",
  MIRROR: "mirror",
};

export function FilterBar({ filters, onChange, counts, maxDepth, shown, total }: Props) {
  const layers = Object.keys(counts.layer).map(Number).sort((a, b) => a - b);
  return (
    <div className="filterbar">
      <input
        type="search"
        className="search"
        placeholder="Filter repos, descriptions, licenses…"
        value={filters.text}
        onChange={(e) => onChange({ ...filters, text: e.target.value })}
        aria-label="Filter dependents"
      />
      <div className="filter-group" role="group" aria-label="Confidence">
        <span className="lbl">Confidence</span>
        {CONFIDENCES.filter((c) => counts.confidence[c]).map((c: Confidence) => (
          <button
            key={c}
            type="button"
            className={`chip ${filters.confidence.includes(c) ? "on" : ""}`}
            aria-pressed={filters.confidence.includes(c)}
            onClick={() => onChange({ ...filters, confidence: toggle(filters.confidence, c) })}
          >
            <span className="dot" style={{ background: `var(--conf-${c})` }} />
            {c} <span className="count">{counts.confidence[c]}</span>
          </button>
        ))}
      </div>
      <div className="filter-group" role="group" aria-label="Relationship">
        <span className="lbl">Relationship</span>
        {RELATIONSHIPS.filter((r) => counts.relationship[r]).map((r) => (
          <button
            key={r}
            type="button"
            className={`chip ${filters.relationship.includes(r) ? "on" : ""}`}
            aria-pressed={filters.relationship.includes(r)}
            onClick={() =>
              onChange({ ...filters, relationship: toggle(filters.relationship, r) })
            }
          >
            {REL_SHORT[r]} <span className="count">{counts.relationship[r]}</span>
          </button>
        ))}
      </div>
      {layers.length > 1 && (
        <div className="filter-group" role="group" aria-label="Evidence layer">
          <span className="lbl">Layer</span>
          {layers.map((l) => (
            <button
              key={l}
              type="button"
              title={LAYER_NAMES[l]}
              className={`chip ${filters.layers.includes(l) ? "on" : ""}`}
              aria-pressed={filters.layers.includes(l)}
              onClick={() => onChange({ ...filters, layers: toggle(filters.layers, l) })}
            >
              L{l} <span className="count">{counts.layer[l]}</span>
            </button>
          ))}
        </div>
      )}
      {maxDepth > 1 && (
        <label className="filter-group">
          <span className="lbl">Depth ≤</span>
          <select
            style={{ width: 80, height: 28 }}
            value={filters.maxDepth ?? ""}
            onChange={(e) =>
              onChange({ ...filters, maxDepth: e.target.value ? Number(e.target.value) : null })
            }
          >
            <option value="">all</option>
            {Array.from({ length: maxDepth }, (_, i) => i + 1).map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        </label>
      )}
      <span className="grow" />
      <span className="small muted">
        {shown === total ? `${total} dependents` : `${shown} of ${total} dependents`}
      </span>
      {isFiltered(filters) && (
        <button type="button" className="btn btn-sm btn-ghost" onClick={() => onChange(emptyFilters)}>
          Clear
        </button>
      )}
    </div>
  );
}
