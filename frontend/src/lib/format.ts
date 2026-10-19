const compact = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });
const plain = new Intl.NumberFormat();

export function fmtCount(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  return Math.abs(n) >= 10000 ? compact.format(n) : plain.format(n);
}

export function fmtScore(n: number | null | undefined): string {
  if (n == null) return "—";
  return n.toFixed(1);
}

export function fmtDuration(seconds: number | null | undefined): string {
  if (seconds == null || seconds < 0) return "—";
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

/** Relative time for a unix timestamp in seconds. */
export function fmtAgo(ts: number | null | undefined, now = Date.now() / 1000): string {
  if (!ts) return "—";
  const d = ts - now;
  const abs = Math.abs(d);
  if (abs < 45) return "just now";
  if (abs < 3600) return rtf.format(Math.round(d / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(d / 3600), "hour");
  return rtf.format(Math.round(d / 86400), "day");
}

export function fmtDate(value: string | null | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleDateString();
}

export function fmtTimestamp(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

export function githubUrl(repo: string): string {
  return /^https?:\/\//.test(repo) ? repo : `https://github.com/${repo}`;
}

export function shortSha(sha: string | null | undefined): string {
  if (!sha) return "—";
  return /^[0-9a-f]{40}$/i.test(sha) ? sha.slice(0, 10) : sha;
}
