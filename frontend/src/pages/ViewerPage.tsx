import { useEffect, useState, type DragEvent, type FormEvent } from "react";
import type { Graph } from "../api/types";
import { GraphResults } from "../components/GraphResults";
import { parseUpload } from "../lib/archive";
import { assertGraph } from "../lib/graph";
import { navigate, useLocation } from "../lib/router";

type Loaded = { graph: Graph; label: string; snippets?: Map<string, string> };

async function fetchGraph(url: string): Promise<Graph> {
  let resp: Response;
  try {
    resp = await fetch(url, { headers: { Accept: "application/json" } });
  } catch {
    throw new Error(
      "The request failed. If the file is on another site, that site must allow cross-origin requests (raw.githubusercontent.com does).",
    );
  }
  if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`);
  const data: unknown = await resp.json().catch(() => {
    throw new Error("The response isn't valid JSON.");
  });
  assertGraph(data);
  return data;
}

/**
 * Standalone viewer for any dependency_graph.json: from a URL (?url=…, e.g.
 * raw.githubusercontent.com or a GitHub Action artifact host) or a local file.
 * Replaces the old external dashboard's ?url= link.
 */
export function ViewerPage() {
  const { search } = useLocation();
  const urlParam = search.get("url") ?? "";
  const [input, setInput] = useState(urlParam);
  const [fileLoaded, setFileLoaded] = useState<Loaded | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  // Result of fetching ?url=, keyed by the URL it belongs to.
  const [fetched, setFetched] = useState<{ url: string; loaded?: Loaded; error?: string } | null>(null);
  const [over, setOver] = useState(false);

  useEffect(() => {
    if (!urlParam) return;
    let cancelled = false;
    fetchGraph(urlParam)
      .then((graph) => {
        if (!cancelled) setFetched({ url: urlParam, loaded: { graph, label: urlParam } });
      })
      .catch((e: Error) => {
        if (!cancelled) setFetched({ url: urlParam, error: e.message });
      });
    return () => {
      cancelled = true;
    };
  }, [urlParam]);

  const current = fetched && fetched.url === urlParam ? fetched : null;
  const loading = Boolean(urlParam) && !current;
  const loaded = urlParam ? (current?.loaded ?? null) : fileLoaded;
  const error = urlParam ? (current?.error ?? null) : fileError;

  const openUrl = (e: FormEvent) => {
    e.preventDefault();
    const u = input.trim();
    if (u) navigate(`/view?url=${encodeURIComponent(u)}`);
  };

  const readFile = async (file: File) => {
    setFileError(null);
    try {
      const { graph, snippets } = parseUpload(new Uint8Array(await file.arrayBuffer()));
      setFileLoaded({ graph, label: file.name, snippets });
      if (urlParam) navigate("/view", { replace: true });
    } catch (e) {
      setFileError(`${file.name}: ${(e as Error).message}`);
      if (urlParam) navigate("/view", { replace: true });
    }
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    const f = e.dataTransfer.files[0];
    if (f) void readFile(f);
  };

  if (loaded) {
    return (
      <div className="stack">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <span className="small muted truncate">Viewing {loaded.label}</span>
          <button
            className="btn btn-sm"
            onClick={() => {
              setFileLoaded(null);
              navigate("/view");
            }}
          >
            Open another graph
          </button>
        </div>
        <GraphResults
          graph={loaded.graph}
          sourceLabel="Imported graph"
          loadSnippet={
            loaded.snippets?.size
              ? async (p) => {
                  const raw = loaded.snippets?.get(p.split("/").pop() ?? p);
                  if (raw == null) throw new Error("This snippet isn't in the uploaded archive.");
                  return JSON.parse(raw);
                }
              : undefined
          }
        />
      </div>
    );
  }

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Open a graph</h1>
          <p className="sub">
            View any <code>dependency_graph.json</code> — from a GitHub Action run, a data
            repository, or your disk. Files are read in your browser; nothing is uploaded.
          </p>
        </div>
      </div>
      <div className="card card-pad stack">
        <form onSubmit={openUrl} className="row">
          <input
            type="url"
            className="grow"
            placeholder="https://raw.githubusercontent.com/org/repo/main/dependency_graph.json"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="Graph URL"
            style={{ flex: 1 }}
          />
          <button className="btn btn-primary" type="submit" disabled={loading || !input.trim()}>
            {loading ? "Loading…" : "Open URL"}
          </button>
        </form>
        <div
          className={`dropzone ${over ? "over" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setOver(true);
          }}
          onDragLeave={() => setOver(false)}
          onDrop={onDrop}
        >
          <p>
            Drop a <code>dependency_graph.json</code> or the Action's artifact <code>.zip</code>{" "}
            (graph + SPDX snippets) here, or
          </p>
          <label className="btn" style={{ marginTop: 8 }}>
            Choose file…
            <input
              type="file"
              accept="application/json,.json,application/zip,.zip"
              className="sr-only"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void readFile(f);
              }}
            />
          </label>
        </div>
        {error && <div className="banner danger">{error}</div>}
        <p className="small muted">
          Tip: link straight to a rendered graph with{" "}
          <code>{`${window.location.origin}/view?url=<graph-url>`}</code> — handy for README badges.
        </p>
      </div>
    </div>
  );
}
