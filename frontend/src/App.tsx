import { useEffect, useState } from "react";
import { api } from "./api/client";
import type { Health } from "./api/types";
import { Link, matchPath, useLocation } from "./lib/router";
import { JobDetailPage } from "./pages/JobDetailPage";
import { JobsPage } from "./pages/JobsPage";
import { NewAuditPage } from "./pages/NewAuditPage";
import { ViewerPage } from "./pages/ViewerPage";

function Logo() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <circle cx="7" cy="12" r="3" />
      <circle cx="19" cy="6" r="2" />
      <circle cx="19" cy="18" r="2" />
      <path d="M10 12h3.5" />
      <path d="M9.6 10.5l7.5-3.7" />
      <path d="M9.6 13.5l7.5 3.7" />
    </svg>
  );
}

function WorkerPill() {
  const [health, setHealth] = useState<Health | null>(null);
  const [down, setDown] = useState(false);
  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .health()
        .then((h) => {
          if (!alive) return;
          setHealth(h);
          setDown(false);
        })
        .catch(() => alive && setDown(true));
    load();
    const t = setInterval(load, 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);
  if (down) {
    return (
      <span className="worker-pill">
        <span className="dot" style={{ background: "var(--danger)" }} /> API unreachable
      </span>
    );
  }
  if (!health) return null;
  const w = health.worker;
  return (
    <span className="worker-pill" title={w.lastSeen ? `last heartbeat ${new Date(w.lastSeen * 1000).toLocaleTimeString()}` : undefined}>
      <span className="dot" style={{ background: w.alive ? "var(--ok)" : "var(--danger)" }} />
      {w.alive ? `worker online · ${w.inflight ?? 0}/${w.concurrency ?? "?"} busy` : "worker offline"}
    </span>
  );
}

export function App() {
  const { pathname } = useLocation();
  const job = matchPath("/audits/:id", pathname);

  let page;
  let section: "new" | "audits" | "view" | null = null;
  if (pathname === "/") {
    page = <NewAuditPage />;
    section = "new";
  } else if (pathname === "/audits") {
    page = <JobsPage />;
    section = "audits";
  } else if (job) {
    page = <JobDetailPage key={job.id} id={job.id} />;
    section = "audits";
  } else if (pathname === "/view") {
    page = <ViewerPage />;
    section = "view";
  } else {
    page = (
      <div className="empty">
        Page not found. <Link to="/">Start an audit</Link>.
      </div>
    );
  }

  useEffect(() => {
    const titles = { new: "New audit", audits: "Audits", view: "Graph viewer" };
    document.title = section ? `${titles[section]} · Dependent Audit` : "Dependent Audit";
  }, [section]);

  return (
    <>
      <header className="topbar">
        <Link to="/" className="brand">
          <Logo /> <span className="brand-text">Dependent Audit</span>
        </Link>
        <nav className="nav">
          <Link to="/" className={section === "new" ? "active" : ""}>New audit</Link>
          <Link to="/audits" className={section === "audits" ? "active" : ""}>Audits</Link>
          <Link to="/view" className={section === "view" ? "active" : ""}>Open graph</Link>
        </nav>
        <span className="spacer" />
        <WorkerPill />
      </header>
      <main>{page}</main>
    </>
  );
}
