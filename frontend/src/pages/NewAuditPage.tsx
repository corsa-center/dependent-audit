import { useEffect, useMemo, useState, type FormEvent } from "react";
import { api, ApiError } from "../api/client";
import type { Health, OptionSpec } from "../api/types";
import { navigate } from "../lib/router";

type Value = string | boolean;

// Laid out by hand at the top of the form; everything else renders generically
// from /api/options, so new crawler flags appear without frontend changes.
const PRIMARY = ["repo", "name", "depth", "no_citations", "sg_count"];

const GROUP_TITLES: Record<string, string> = {
  discovery: "Discovery & identifier tuning",
  citations: "Citations & papers",
  advanced: "Advanced",
};

/** Accept "owner/repo", a GitHub URL, or "github.com/owner/repo". */
export function normalizeRepo(input: string): string {
  let s = input.trim();
  s = s.replace(/^https?:\/\//, "").replace(/^(www\.)?github\.com\//, "");
  s = s.replace(/\.git$/, "").replace(/\/+$/, "");
  const parts = s.split("/").filter(Boolean);
  return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : s;
}

function defaultValue(o: OptionSpec): Value {
  if (o.kind === "flag") return false;
  return o.default != null ? String(o.default) : "";
}

function Field({
  opt,
  value,
  onChange,
}: {
  opt: OptionSpec;
  value: Value;
  onChange: (v: Value) => void;
}) {
  const id = `opt-${opt.key}`;
  if (opt.kind === "flag") {
    return (
      <label className="check" htmlFor={id}>
        <input id={id} type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />
        <span>
          <span className="field-label mono">{opt.flag}</span>
          {opt.help && <div className="field-help">{opt.help}</div>}
        </span>
      </label>
    );
  }
  return (
    <label className="field" htmlFor={id}>
      <span className="field-label mono">{opt.flag}</span>
      {opt.kind === "choice" ? (
        <select id={id} value={String(value)} onChange={(e) => onChange(e.target.value)}>
          {(opt.choices ?? []).map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
      ) : opt.key === "custom_string" ? (
        <textarea id={id} rows={3} value={String(value)} onChange={(e) => onChange(e.target.value)} spellCheck={false} />
      ) : (
        <input
          id={id}
          type={opt.kind === "int" || opt.kind === "float" ? "number" : "text"}
          step={opt.kind === "float" ? "any" : undefined}
          min={opt.min}
          value={String(value)}
          onChange={(e) => onChange(e.target.value)}
          spellCheck={false}
        />
      )}
      {opt.help && <span className="field-help">{opt.help}</span>}
    </label>
  );
}

export function NewAuditPage() {
  const [options, setOptions] = useState<OptionSpec[] | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [values, setValues] = useState<Record<string, Value>>({});
  const [nameTouched, setNameTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    api
      .options()
      .then((r) => {
        setOptions(r.options);
        setValues(Object.fromEntries(r.options.map((o) => [o.key, defaultValue(o)])));
      })
      .catch((e: Error) => setLoadError(e.message));
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);

  const byKey = useMemo(() => new Map((options ?? []).map((o) => [o.key, o])), [options]);
  const groups = useMemo(() => {
    const g: Record<string, OptionSpec[]> = {};
    for (const o of options ?? []) {
      if (PRIMARY.includes(o.key)) continue;
      (g[o.group] ??= []).push(o);
    }
    return g;
  }, [options]);

  const set = (key: string, v: Value) => setValues((prev) => ({ ...prev, [key]: v }));

  const onRepoChange = (raw: string) => {
    setValues((prev) => {
      const next: Record<string, Value> = { ...prev, repo: raw };
      if (!nameTouched) {
        const repo = normalizeRepo(raw);
        next.name = repo.includes("/") ? repo.split("/")[1].toLowerCase() : "";
      }
      return next;
    });
  };

  const depth = Number(values.depth ?? 1);
  const needsSg = depth > 0;
  const workerDown = health && !health.worker.alive;
  const missingSg = health?.worker.alive && !health.worker.sgToken && needsSg;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!options) return;
    setError(null);
    const payload: Record<string, unknown> = {};
    for (const o of options) {
      let v = values[o.key];
      if (o.key === "repo") v = normalizeRepo(String(v ?? ""));
      if (o.kind === "flag") {
        if (v) payload[o.key] = true;
        continue;
      }
      const s = String(v ?? "").trim();
      if (!s) continue;
      if (!o.required && o.default != null && s === String(o.default)) continue; // CLI default
      payload[o.key] = o.kind === "int" ? parseInt(s, 10) : o.kind === "float" ? parseFloat(s) : s;
    }
    setSubmitting(true);
    try {
      const job = await api.submit(payload);
      navigate(`/audits/${job.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
      setSubmitting(false);
    }
  };

  if (loadError) {
    return (
      <div className="banner danger">
        Couldn't reach the audit API: {loadError}. Is the service running?
      </div>
    );
  }
  if (!options) return <div className="empty">Loading…</div>;

  const opt = (k: string) => byKey.get(k);

  return (
    <form onSubmit={submit} className="stack">
      <div className="page-head">
        <div>
          <h1>New audit</h1>
          <p className="sub">
            Find public repositories that depend on a C/C++ project, score each dependency, and
            collect the papers that cite it.
          </p>
        </div>
      </div>

      {workerDown && (
        <div className="banner danger">
          No audit worker has checked in recently. Audits will queue until one is running.
        </div>
      )}
      {missingSg && (
        <div className="banner warn">
          The worker has no Sourcegraph token configured, so only depth 0 (root metadata and
          citations) can run. Set <code>SG_TOKEN</code> in the service environment.
        </div>
      )}
      {health?.worker.alive && !health.worker.ghToken && (
        <div className="banner info">
          No GitHub token configured: repository metadata (stars, license) and seminal-paper
          discovery will be limited.
        </div>
      )}

      <div className="card card-pad stack">
        <div className="form-grid">
          <label className="field" htmlFor="opt-repo" style={{ gridColumn: "span 2" }}>
            <span className="field-label">Repository</span>
            <input
              id="opt-repo"
              type="text"
              required
              autoFocus
              placeholder="owner/name or https://github.com/owner/name"
              value={String(values.repo ?? "")}
              onChange={(e) => onRepoChange(e.target.value)}
              spellCheck={false}
            />
            <span className="field-help">{opt("repo")?.help}</span>
          </label>
          <label className="field" htmlFor="opt-name">
            <span className="field-label">Project name</span>
            <input
              id="opt-name"
              type="text"
              required
              value={String(values.name ?? "")}
              onChange={(e) => {
                setNameTouched(true);
                set("name", e.target.value);
              }}
              spellCheck={false}
            />
            <span className="field-help">{opt("name")?.help}</span>
          </label>
          <label className="field" htmlFor="opt-depth">
            <span className="field-label">Depth</span>
            <select id="opt-depth" value={String(values.depth ?? "1")} onChange={(e) => set("depth", e.target.value)}>
              <option value="0">0 — root metadata only</option>
              <option value="1">1 — direct dependents</option>
              <option value="2">2 — dependents of dependents</option>
              <option value="3">3</option>
            </select>
            <span className="field-help">Deeper crawls take much longer.</span>
          </label>
          <label className="field" htmlFor="opt-sg_count">
            <span className="field-label">Match cap</span>
            <input
              id="opt-sg_count"
              type="text"
              value={String(values.sg_count ?? "")}
              onChange={(e) => set("sg_count", e.target.value)}
              spellCheck={false}
            />
            <span className="field-help">{opt("sg_count")?.help} Use “all” if a run reports the limit was hit.</span>
          </label>
          {opt("no_citations") && (
            <div style={{ alignSelf: "center" }}>
              <label className="check" htmlFor="opt-no_citations">
                <input
                  id="opt-no_citations"
                  type="checkbox"
                  checked={Boolean(values.no_citations)}
                  onChange={(e) => set("no_citations", e.target.checked)}
                />
                <span>
                  <span className="field-label">Skip papers</span>
                  <div className="field-help">{opt("no_citations")?.help}</div>
                </span>
              </label>
            </div>
          )}
        </div>

        {Object.entries(groups).map(([group, opts]) => (
          <details key={group} className="group">
            <summary>{GROUP_TITLES[group] ?? group}</summary>
            <div className="form-grid">
              {opts.map((o) => (
                <Field key={o.key} opt={o} value={values[o.key] ?? defaultValue(o)} onChange={(v) => set(o.key, v)} />
              ))}
            </div>
          </details>
        ))}

        {error && <div className="banner danger">{error}</div>}
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button className="btn btn-primary" type="submit" disabled={submitting || !values.repo || !values.name}>
            {submitting ? "Submitting…" : "Start audit"}
          </button>
        </div>
      </div>
    </form>
  );
}
