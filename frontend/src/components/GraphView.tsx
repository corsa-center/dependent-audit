// Interactive dependency graph (Cytoscape, lazy-loaded). Concentric rings by
// BFS depth around the root; node size = log(stars), colour = confidence,
// shape = relationship. Shares the table's filtered rows.
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import { useEffect, useMemo, useRef } from "react";
import type { DependentRow, GraphModel } from "../lib/graph";

export const GRAPH_NODE_CAP = 3000;

const SHAPES: Record<string, cytoscape.Css.NodeShape> = {
  DEPENDS_ON: "ellipse",
  VENDORED: "diamond",
  MIRROR: "triangle",
};

function cssVar(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}

function palette() {
  return {
    high: cssVar("--conf-high"),
    medium: cssVar("--conf-medium"),
    low: cssVar("--conf-low"),
    unknown: cssVar("--conf-unknown"),
    root: cssVar("--root"),
    text: cssVar("--text"),
    muted: cssVar("--text-faint"),
    edge: cssVar("--border-strong"),
    accent: cssVar("--accent"),
    surface: cssVar("--surface"),
  };
}

/**
 * Ring index per node. Rings hold more nodes the further out they are (the
 * circumference grows with the radius), a new depth always starts a new ring,
 * and within a depth the strongest dependents sit innermost.
 */
function assignRings(rows: DependentRow[]): Map<string, number> {
  const sorted = [...rows].sort((a, b) => a.depth - b.depth || b.score - a.score);
  const out = new Map<string, number>();
  let ring = 1;
  let used = 0;
  let depth = sorted[0]?.depth ?? 1;
  const capacity = (k: number) => 8 + 10 * (k - 1);
  for (const r of sorted) {
    if (r.depth !== depth || used >= capacity(ring)) {
      ring += 1;
      used = 0;
      depth = r.depth;
    }
    out.set(r.id, ring);
    used += 1;
  }
  return out;
}

/** Fit the graph, but don't blow a handful of nodes up to fill the canvas. */
function fitCapped(cy: Core) {
  cy.fit(undefined, 30);
  if (cy.zoom() > 1.6) {
    cy.zoom(1.6);
    cy.center();
  }
}

interface Props {
  model: GraphModel;
  rows: DependentRow[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export default function GraphView({ model, rows, selectedId, onSelect }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const onSelectRef = useRef(onSelect);
  useEffect(() => {
    onSelectRef.current = onSelect;
  }, [onSelect]);

  const shown = useMemo(
    () => (rows.length > GRAPH_NODE_CAP ? [...rows].sort((a, b) => b.score - a.score).slice(0, GRAPH_NODE_CAP) : rows),
    [rows],
  );

  // Create the instance once.
  useEffect(() => {
    if (!containerRef.current) return;
    const c = palette();
    const cy = cytoscape({
      container: containerRef.current,
      minZoom: 0.05,
      maxZoom: 4,
      wheelSensitivity: 0.3,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            shape: "data(shape)" as unknown as cytoscape.Css.NodeShape,
            width: "data(size)",
            height: "data(size)",
            label: "data(label)",
            color: c.text,
            "font-size": 10,
            "min-zoomed-font-size": 9,
            "text-valign": "bottom",
            "text-margin-y": 3,
            "text-outline-color": c.surface,
            "text-outline-width": 2,
            "border-width": 0,
          },
        },
        {
          selector: "node.root",
          style: {
            "font-size": 14,
            "font-weight": "bold",
            "min-zoomed-font-size": 0,
            "border-width": 3,
            "border-color": c.surface,
          },
        },
        {
          selector: "edge",
          style: {
            width: 1.2,
            "line-color": c.edge,
            "curve-style": "haystack",
            opacity: 0.7,
          },
        },
        {
          selector: "node:selected",
          style: { "border-width": 3, "border-color": c.accent, "min-zoomed-font-size": 0 },
        },
        {
          selector: "edge.hl",
          style: { "line-color": c.accent, opacity: 1, width: 2, "z-index": 10 },
        },
        { selector: "node.faded", style: { opacity: 0.25 } },
      ],
    });
    cy.on("tap", "node", (evt) => onSelectRef.current(evt.target.id()));
    cy.on("mouseover", "node", (evt) => {
      evt.target.connectedEdges().addClass("hl");
      if (containerRef.current) containerRef.current.style.cursor = "pointer";
    });
    cy.on("mouseout", "node", (evt) => {
      evt.target.connectedEdges().removeClass("hl");
      if (containerRef.current) containerRef.current.style.cursor = "";
    });
    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  // (Re)build elements whenever the filtered set changes.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const c = palette();
    const ids = new Set(shown.map((r) => r.id));
    ids.add(model.rootId);
    const els: ElementDefinition[] = [];
    const rootNode = model.root;
    const rootStars = rootNode?.data?.stars ?? 0;
    els.push({
      group: "nodes",
      data: {
        id: model.rootId,
        label: rootNode?.label ?? model.rootId,
        color: c.root,
        shape: "star",
        size: 40 + 4 * Math.log10(rootStars + 1),
        depth: 0,
      },
      classes: "root",
    });
    for (const r of shown) {
      els.push({
        group: "nodes",
        data: {
          id: r.id,
          label: r.label,
          color: c[r.confidence],
          shape: SHAPES[r.relationship] ?? "ellipse",
          size: 10 + 6 * Math.log10(r.stars + 1),
          depth: r.depth,
        },
      });
    }
    for (const e of model.graph.edges) {
      if (ids.has(e.source) && ids.has(e.target)) {
        els.push({ group: "edges", data: { id: `${e.source}→${e.target}`, source: e.source, target: e.target } });
      }
    }
    const rings = assignRings(shown);
    cy.batch(() => {
      cy.elements().remove();
      cy.add(els);
    });
    cy.layout({
      name: "concentric",
      // Root in the centre, then rings filled outward by depth, then score:
      // distance from the root reads as "how far / how weak".
      concentric: (n) => (n.id() === model.rootId ? 1e6 : 1e6 - (rings.get(n.id()) ?? 1e5)),
      levelWidth: () => 1,
      minNodeSpacing: 6,
      spacingFactor: 0.9,
      animate: false,
      avoidOverlap: true,
    } as cytoscape.LayoutOptions).run();
    fitCapped(cy);
  }, [model, shown]);

  // Reflect the external selection.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes(":selected").unselect();
    if (selectedId) {
      const n = cy.getElementById(selectedId);
      if (n.nonempty()) n.select();
    }
  }, [selectedId, shown]);

  const fit = () => {
    if (cyRef.current) fitCapped(cyRef.current);
  };
  const zoom = (f: number) => {
    const cy = cyRef.current;
    if (cy) cy.zoom({ level: cy.zoom() * f, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };

  return (
    <div className="graph-wrap">
      <div ref={containerRef} className="graph-canvas" role="img" aria-label="Dependency graph" />
      <div className="graph-tools">
        <button className="btn btn-sm" onClick={() => zoom(1.25)} aria-label="Zoom in">+</button>
        <button className="btn btn-sm" onClick={() => zoom(0.8)} aria-label="Zoom out">−</button>
        <button className="btn btn-sm" onClick={fit}>Fit</button>
      </div>
      <div className="graph-legend">
        <div className="legend-row"><span className="dot" style={{ background: "var(--root)" }} /> root</div>
        {(["high", "medium", "low"] as const).map((t) => (
          <div key={t} className="legend-row">
            <span className="dot" style={{ background: `var(--conf-${t})` }} /> {t} confidence
          </div>
        ))}
        <div className="legend-row faint">● depends · ◆ vendored · ▲ mirror · size = stars</div>
        {rows.length > GRAPH_NODE_CAP && (
          <div className="legend-row" style={{ color: "var(--warn)" }}>
            Showing top {GRAPH_NODE_CAP} of {rows.length} by score
          </div>
        )}
      </div>
    </div>
  );
}
