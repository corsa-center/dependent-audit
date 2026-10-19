import { useEffect, useReducer, useRef, useState } from "react";
import { api, ApiError, links } from "../api/client";
import type { StreamedEvent } from "../api/events";
import { TERMINAL } from "../api/types";
import {
  applyEvents,
  initialProgress,
  type ProgressState,
} from "../state/progressReducer";

export type StreamState = "connecting" | "open" | "reconnecting" | "closed";

function reducer(state: ProgressState, batch: StreamedEvent[]) {
  return applyEvents(state, batch);
}

function isTerminal(ev: StreamedEvent) {
  return ev.type === "job" && TERMINAL.has(ev.data.status);
}

/**
 * Follow a job's progress stream.
 *
 * EventSource resumes by itself (Last-Event-ID) when the server ends a bounded
 * stream. When the browser gives up (readyState CLOSED: a 204 once the job is
 * finished and fully replayed, or an HTTP error), we check the job and, if it
 * is still live, reopen with ?lastEventId= after a backoff. Events are queued
 * and folded into state once per animation frame.
 */
export function useJobEvents(jobId: string, enabled = true) {
  const [state, dispatch] = useReducer(reducer, initialProgress);
  const [stream, setStream] = useState<StreamState>("connecting");
  const lastIdRef = useRef(-1);

  useEffect(() => {
    if (!enabled) return;
    let es: EventSource | null = null;
    let disposed = false;
    let finished = false;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let raf = 0;
    let backoff = 1000;
    const queue: StreamedEvent[] = [];

    const flush = () => {
      raf = 0;
      if (queue.length) dispatch(queue.splice(0, queue.length));
    };

    const open = () => {
      if (disposed || finished) return;
      const base = links.events(jobId);
      const url = lastIdRef.current >= 0 ? `${base}?lastEventId=${lastIdRef.current}` : base;
      es = new EventSource(url);
      es.onopen = () => {
        backoff = 1000;
        setStream("open");
      };
      es.onmessage = (msg) => {
        let ev: StreamedEvent;
        try {
          ev = { ...JSON.parse(msg.data), id: Number(msg.lastEventId) };
        } catch {
          return;
        }
        if (ev.id <= lastIdRef.current) return;
        lastIdRef.current = ev.id;
        queue.push(ev);
        if (!raf) raf = requestAnimationFrame(flush);
        if (isTerminal(ev)) {
          finished = true;
          es?.close();
          setStream("closed");
        }
      };
      es.onerror = () => {
        if (finished || disposed || !es) return;
        if (es.readyState === EventSource.CONNECTING) {
          setStream("reconnecting"); // browser-managed resume
          return;
        }
        es.close();
        void recover();
      };
    };

    const recover = async () => {
      try {
        const meta = await api.getJob(jobId);
        if (TERMINAL.has(meta.status)) {
          // The job is done and the server had nothing left to send (a 204),
          // or it predates event logs. Nothing more will come.
          finished = true;
          setStream("closed");
          return;
        }
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) {
          finished = true; // job deleted
          setStream("closed");
          return;
        }
        // otherwise the backend is unreachable — keep retrying
      }
      if (disposed) return;
      setStream("reconnecting");
      retryTimer = setTimeout(open, backoff);
      backoff = Math.min(backoff * 2, 15000);
    };

    open();
    return () => {
      disposed = true;
      es?.close();
      if (retryTimer) clearTimeout(retryTimer);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [jobId, enabled]);

  return { state, stream };
}
