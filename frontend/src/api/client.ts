import type { Graph, Health, JobMeta, OptionSpec } from "./types";

export class ApiError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(path, {
    ...init,
    headers: { Accept: "application/json", ...(init?.headers ?? {}) },
  });
  if (resp.status === 204) return undefined as T;
  const text = await resp.text();
  let body: unknown = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    // non-JSON body (e.g. an nginx error page)
  }
  if (!resp.ok) {
    const msg =
      body && typeof body === "object" && "error" in body
        ? String((body as { error: unknown }).error)
        : `${resp.status} ${resp.statusText}`;
    throw new ApiError(resp.status, msg, body);
  }
  return body as T;
}

export const api = {
  health: () => request<Health>("/api/health"),
  options: () =>
    request<{ options: OptionSpec[]; allowPayloadTokens: boolean }>("/api/options"),
  listJobs: (limit = 100) =>
    request<{ jobs: JobMeta[] }>(`/api/jobs?limit=${limit}`).then((r) => r.jobs),
  getJob: (id: string) => request<JobMeta>(`/api/jobs/${encodeURIComponent(id)}`),
  submit: (payload: Record<string, unknown>) =>
    request<JobMeta>("/api/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  cancel: (id: string) =>
    request<{ id: string; status: string }>(
      `/api/jobs/${encodeURIComponent(id)}/cancel`,
      { method: "POST" },
    ),
  remove: (id: string) =>
    request<void>(`/api/jobs/${encodeURIComponent(id)}`, { method: "DELETE" }),
  graph: (id: string) => request<Graph>(`/api/jobs/${encodeURIComponent(id)}/graph`),
  /** One SPDX snippet, by a node's `snippetPath` (only its basename is used). */
  snippet: (id: string, snippetPath: string) =>
    request<unknown>(
      `/api/jobs/${encodeURIComponent(id)}/spdx/${encodeURIComponent(snippetPath.split("/").pop() ?? "")}`,
    ),
  log: async (id: string, tail = 300) => {
    const resp = await fetch(`/api/jobs/${encodeURIComponent(id)}/log?tail=${tail}`);
    return resp.ok ? resp.text() : "";
  },
};

export const links = {
  graphDownload: (id: string) => `/api/jobs/${encodeURIComponent(id)}/graph?download=1`,
  graphRaw: (id: string) => `/api/jobs/${encodeURIComponent(id)}/graph`,
  spdx: (id: string) => `/api/jobs/${encodeURIComponent(id)}/spdx`,
  events: (id: string) => `/api/jobs/${encodeURIComponent(id)}/events`,
};
