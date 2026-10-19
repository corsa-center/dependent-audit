import { strToU8, zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { parseUpload } from "./archive";

const graph = { meta: { root: "a/b" }, nodes: [{ id: "a/b" }], edges: [] };

describe("parseUpload", () => {
  it("reads a bare graph JSON", () => {
    const up = parseUpload(strToU8(JSON.stringify(graph)));
    expect(up.graph.meta.root).toBe("a/b");
    expect(up.snippets.size).toBe(0);
  });

  it("reads the Action artifact zip: graph + SPDX snippets", () => {
    const zip = zipSync({
      "notes.json": strToU8('{"not":"a graph"}'),
      "dependency_graph.json": strToU8(JSON.stringify(graph)),
      "spdx_snippets/x_y.spdx.json": strToU8('{"spdxVersion":"SPDX-2.3"}'),
    });
    const up = parseUpload(zip);
    expect(up.graph.meta.root).toBe("a/b");
    expect(JSON.parse(up.snippets.get("x_y.spdx.json")!).spdxVersion).toBe("SPDX-2.3");
  });

  it("finds a renamed graph inside a zip, and rejects archives without one", () => {
    expect(parseUpload(zipSync({ "out/zfp.json": strToU8(JSON.stringify(graph)) })).graph.nodes).toHaveLength(1);
    expect(() => parseUpload(zipSync({ "a.json": strToU8("{}") }))).toThrow(/doesn't contain/);
    expect(() => parseUpload(strToU8("not json"))).toThrow(/valid JSON/);
  });
});
