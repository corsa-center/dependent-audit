// Reads what the viewer can be handed: a bare dependency_graph.json, or the
// GitHub Action's artifact .zip (graph + spdx_snippets/). Entirely in-browser.
import { strFromU8, unzipSync } from "fflate";
import type { Graph } from "../api/types";
import { assertGraph } from "./graph";

export interface Upload {
  graph: Graph;
  /** SPDX snippets keyed by basename (a node's snippetPath's last segment). */
  snippets: Map<string, string>;
}

const basename = (p: string) => p.split("/").pop() ?? p;

function isZip(bytes: Uint8Array) {
  return bytes.length > 3 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
}

export function parseUpload(bytes: Uint8Array): Upload {
  if (!isZip(bytes)) {
    let data: unknown;
    try {
      data = JSON.parse(strFromU8(bytes));
    } catch {
      throw new Error("Not valid JSON (or a .zip archive).");
    }
    assertGraph(data);
    return { graph: data, snippets: new Map() };
  }

  const files = unzipSync(bytes, {
    // Skip directories and anything that isn't JSON; guards memory on odd zips.
    filter: (f) => f.name.endsWith(".json") && !f.name.startsWith("__MACOSX/"),
  });
  const snippets = new Map<string, string>();
  const candidates: [string, Uint8Array][] = [];
  for (const [name, data] of Object.entries(files)) {
    if (name.endsWith(".spdx.json")) snippets.set(basename(name), strFromU8(data));
    else candidates.push([name, data]);
  }
  // Prefer the conventional name, then any JSON that is shaped like a graph.
  candidates.sort(
    ([a], [b]) =>
      Number(basename(b) === "dependency_graph.json") - Number(basename(a) === "dependency_graph.json") ||
      a.localeCompare(b),
  );
  for (const [, data] of candidates) {
    try {
      const parsed: unknown = JSON.parse(strFromU8(data));
      assertGraph(parsed);
      return { graph: parsed, snippets };
    } catch {
      // not the graph; keep looking
    }
  }
  throw new Error("The archive doesn't contain a dependency graph JSON.");
}
