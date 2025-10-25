// MITMSimulation.jsx  (fixed summary & reliable counters, cinematic summary animation every session)
import "./MITMReplay.css";
import React, { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { saveAs } from "file-saver";
import {
  Play,
  Square,
  Download,
  Activity,
  Zap,
  FilePlus,
  RotateCw,
  AlertCircle,
} from "lucide-react";

/*
  MITMSimulation.jsx (fixed)
  - Uses countersRef to ensure session summary reads the latest counters
  - Alerts = simulated credential/sensitive captures (demo-only)
  - Cinematic "mission complete" animation runs every session end
*/

const METHODS = ["GET", "POST", "PUT", "DELETE"];
const PATHS = ["/login", "/api/user", "/api/items", "/search?q=bag", "/cart", "/checkout", "/messages", "/profile"];
const HOSTS = ["example.com", "shop.test", "api.service", "demo.local"];
const NAMES = ["alice", "bob", "charlie", "dani", "eve"];
const STATUS_CODES = [200, 200, 201, 204, 400, 401, 403, 404, 500];

let globalId = 0;
const defaultInterval = 1200;
const defaultCap = 250;
const defaultSessionSeconds = 12;

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}
function safePretty(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

export default function MITMSimulation({
  autoInterval = defaultInterval,
  capFlows = defaultCap,
  sessionDuration = defaultSessionSeconds, // seconds per run
  onExport,
}) {
  // UI & simulation state
  const [running, setRunning] = useState(false);
  const [flows, setFlows] = useState([]); // newest-first
  const [logs, setLogs] = useState([]); // newest-first
  const [counters, setCounters] = useState({ intercepted: 0, modified: 0, alerts: 0 });
  const countersRef = useRef({ intercepted: 0, modified: 0, alerts: 0 }); // <-- REF that always holds latest counters
  const [selectedIndex, setSelectedIndex] = useState(0); // 0 = newest
  const [sessionProgress, setSessionProgress] = useState(0); // 0-100
  const [summary, setSummary] = useState(null);

  const intervalRef = useRef(null);
  const progressRef = useRef(null);
  const sessionTimeoutRef = useRef(null);
  const logsRef = useRef(null);
  const newestLogIdRef = useRef(null);

  // keep countersRef synced whenever counters state changes
  useEffect(() => {
    countersRef.current = counters;
  }, [counters]);

  // auto-scroll when logs change (newest at top)
  useEffect(() => {
    if (logsRef.current) {
      setTimeout(() => {
        logsRef.current.scrollTop = 0;
      }, 40);
    }
  }, [logs]);

  // helpers (same realistic demo logic)
  function createRequest() {
    const id = ++globalId;
    const method = pick(METHODS);
    const host = pick(HOSTS);
    const path = pick(PATHS);
    const url = `https://${host}${path}`;
    const headers = {
      Host: host,
      "User-Agent": "DemoBrowser/1.0",
      Accept: "application/json",
      Cookie: Math.random() < 0.6 ? `session=${Math.random().toString(36).slice(2, 10)}` : undefined,
      Authorization: Math.random() < 0.25 ? `Bearer ${Math.random().toString(36).slice(2, 12)}` : undefined,
    };
    if (!headers.Cookie) delete headers.Cookie;
    if (!headers.Authorization) delete headers.Authorization;

    const body = method === "GET" ? null : {
      username: pick(NAMES),
      amount: randInt(1, 9999),
      comment: Math.random() < 0.2 ? "<script>alert(1)</script>" : "demo"
    };

    return {
      id,
      t: Math.round(Date.now() / 1000),
      method,
      url,
      headers,
      body
    };
  }

  function createOriginalResponse(req) {
    const status = pick(STATUS_CODES);
    const latency = randInt(20, 600);
    const headers = {
      "Content-Type": "application/json",
      Server: "demo-server/1.2",
      "Cache-Control": "no-cache"
    };
    const body = (status >= 200 && status < 300)
      ? { ok: true, data: { message: "Success", user: req.body?.username || null } }
      : { ok: false, error: "Request failed" };

    return { status, latency, headers, body };
  }

  function createModifiedResponse(req, origRes) {
    const mod = JSON.parse(JSON.stringify(origRes));
    const notes = [];
    let alert = null;

    // remove sensitive headers sometimes
    if (Math.random() < 0.35 && req.headers.Cookie) {
      delete req.headers.Cookie;
      notes.push("Request Cookie removed");
    }
    if (Math.random() < 0.25 && req.headers.Authorization) {
      delete req.headers.Authorization;
      notes.push("Authorization header stripped");
    }

    // inject tracking header
    if (Math.random() < 0.45) {
      mod.headers["X-Intercepted-By"] = "mitm-demo";
      notes.push("X-Intercepted-By injected");
    }

    // modify body or escalate status sometimes
    if (mod.body && typeof mod.body === "object") {
      if (mod.body.data && mod.body.data.message && Math.random() < 0.35) {
        mod.body.data.message = `${mod.body.data.message} (modified)`;
        notes.push("Response message modified");
      }
      if (mod.body.data && mod.body.data.user && Math.random() < 0.25) {
        mod.body.data.user = `${mod.body.data.user}_leak`;
        notes.push("User field altered");
      }
      if (!mod.body.data && Math.random() < 0.12) {
        mod.status = 500;
        mod.body = { ok: false, error: "Internal error (tampered)" };
        notes.push("Status escalated to 500");
      }
    }

    // latency spike sometimes
    if (Math.random() < 0.18) {
      mod.latency = mod.latency + randInt(80, 800);
      notes.push("Artificial latency introduced");
    }

    // credential alert
    if (req.body && req.body.username && Math.random() < 0.2) {
      alert = `Credential captured: ${req.body.username}`;
      notes.push("Possible credential captured");
    }

    return { modified: mod, notes, alert };
  }

  // generate a single flow
  function generateFlow() {
    const req = createRequest();
    const orig = createOriginalResponse(req);
    const { modified, notes, alert } = createModifiedResponse(JSON.parse(JSON.stringify(req)), orig);

    const flow = {
      id: req.id,
      t: req.t,
      request: req,
      original_response: orig,
      modified_response: modified,
      notes,
      alert,
      simulated_at: new Date().toISOString()
    };

    // push newest-first and cap
    setFlows(prev => [flow, ...prev].slice(0, capFlows));

    // logs newest-first
    setLogs(prev => [({
      id: flow.id,
      t: flow.t,
      method: flow.request.method,
      url: flow.request.url,
      change: notes.length ? notes.join("; ") : "Observed",
      alert: alert || null
    }), ...prev].slice(0, 500));

    // update counters reliably via functional updater and sync ref
    setCounters(prev => {
      const next = {
        intercepted: prev.intercepted + 1,
        modified: prev.modified + (notes.length ? 1 : 0),
        alerts: prev.alerts + (alert ? 1 : 0)
      };
      countersRef.current = next; // keep ref in sync
      return next;
    });

    // select newest
    setSelectedIndex(0);
    newestLogIdRef.current = `${flow.id}-${Date.now()}`;
  }

  // session lifecycle with fixed summary logic (uses countersRef)
  function start() {
    if (running) return;
    setSummary(null);
    setSessionProgress(0);
    setRunning(true);
    generateFlow(); // immediate tick

    // reset refs and counters on start to avoid leftover values
    countersRef.current = { intercepted: 0, modified: 0, alerts: 0 };
    setCounters({ intercepted: 0, modified: 0, alerts: 0 });
    setFlows([]);
    setLogs([]);

    intervalRef.current = setInterval(generateFlow, autoInterval);

    const startTs = Date.now();
    progressRef.current = setInterval(() => {
      const elapsed = (Date.now() - startTs) / 1000;
      const percent = Math.min(100, Math.round((elapsed / sessionDuration) * 100));
      setSessionProgress(percent);
    }, 150);

    // session timeout — when it ends, build summary from countersRef (which is always latest)
    sessionTimeoutRef.current = setTimeout(() => {
      // stop everything
      if (intervalRef.current) clearInterval(intervalRef.current);
      intervalRef.current = null;
      if (progressRef.current) clearInterval(progressRef.current);
      progressRef.current = null;
      setRunning(false);
      setSessionProgress(100);

      // Wait a short moment so React finishes last renders, then read countersRef
      setTimeout(() => {
        const liveCounters = countersRef.current || { intercepted: 0, modified: 0, alerts: 0 };
        // Use intercepted from countersRef for totalIntercepted so it is 100% reliable
        const totalIntercepted = liveCounters.intercepted;
        const summaryObj = {
          id: `summary-${Date.now()}`, // unique per session so animation always triggers
          ended_at: new Date().toISOString(),
          duration_s: sessionDuration,
          total_intercepted: totalIntercepted,
          total_modified: liveCounters.modified,
          total_alerts: liveCounters.alerts,
        };
        setSummary(summaryObj);
      }, 220); // 220ms gives React a tick to flush
    }, sessionDuration * 1000);
  }

  function stop() {
    if (!running) return;
    const ok = window.confirm("Stop auto-generation early? Flows will be preserved.");
    if (!ok) return;
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (progressRef.current) clearInterval(progressRef.current);
    if (sessionTimeoutRef.current) clearTimeout(sessionTimeoutRef.current);
    intervalRef.current = null;
    progressRef.current = null;
    sessionTimeoutRef.current = null;
    setRunning(false);
    setSessionProgress(0);
    setSummary(null);
  }

  function reset() {
    const ok = window.confirm("Reset will clear all flows & logs. Continue?");
    if (!ok) return;
    stop();
    setFlows([]);
    setLogs([]);
    setCounters({ intercepted: 0, modified: 0, alerts: 0 });
    countersRef.current = { intercepted: 0, modified: 0, alerts: 0 };
    setSelectedIndex(0);
    setSessionProgress(0);
    setSummary(null);
    globalId = 0;
  }

  function exportAll() {
    if (!flows.length) return alert("No flows to export.");
    const blob = new Blob([JSON.stringify({ exported_at: new Date().toISOString(), flows }, null, 2)], { type: "application/json" });
    saveAs(blob, `mitm_flows_${Date.now()}.json`);
    if (onExport) onExport(flows);
  }
  function exportSelected() {
    const f = flows[selectedIndex];
    if (!f) return alert("No flow selected.");
    const blob = new Blob([JSON.stringify(f, null, 2)], { type: "application/json" });
    saveAs(blob, `mitm_flow_${f.id}_${Date.now()}.json`);
    if (onExport) onExport(f);
  }
  function exportLogsCSV() {
    if (!logs.length) return alert("No logs to export.");
    const header = "time,method,url,change,alert\n";
    const lines = logs.map(l => `${l.t},${l.method},"${l.url.replace(/"/g,'""')}","${l.change.replace(/"/g,'""')}","${(l.alert||"").replace(/"/g,'""')}"`);
    const blob = new Blob([header + lines.join("\n")], { type: "text/csv;charset=utf-8;" });
    saveAs(blob, `mitm_logs_${Date.now()}.csv`);
  }

  const selectedFlow = flows[selectedIndex] || null;

  return (
    <div className="dos-dashboard-sandbox mitm-dashboard">
      <header className="dd-header">
        <div className="left">
          <h2 className="title neon"><Activity size={20} /> MITM Simulation (Sandbox)</h2>
          <div className="subtitle">Auto-generated interception demo • Safe & local-only</div>
        </div>

        <div className="right">
          <div className={`indicator ${running ? "live" : "idle"}`}>
            <span className="dot" />
            <span>{running ? "Running" : "Idle"}</span>
          </div>
        </div>
      </header>

      {/* Controls / quick stats (3 cards layout style) */}
      <section className="grid-controls" style={{ marginBottom: 12 }}>
        <div className="card">
          <div className="card-head"><Zap size={16} /> Controls</div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button className="action start" onClick={start} disabled={running}><Play /> Start</button>
            <button className="action stop" onClick={stop} disabled={!running}><Square /> Stop</button>
            <button className="action finish" onClick={exportAll} disabled={!flows.length}><Download /> Export All</button>
            <button className="export" onClick={exportLogsCSV} disabled={!logs.length}><FilePlus /> Logs CSV</button>
            <button className="mitm-btn" onClick={reset}><RotateCw /> Reset</button>
          </div>

          <div style={{ marginTop: 12, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
            <div className="stat-mini"><strong>Intercepted</strong><div className="muted">{counters.intercepted}</div></div>
            <div className="stat-mini"><strong>Modified</strong><div className="muted">{counters.modified}</div></div>
            <div className="stat-mini"><strong>Alerts</strong><div style={{ color: counters.alerts ? "var(--bad)" : "var(--muted)" }}>{counters.alerts}</div></div>
          </div>

          {/* Animated summary — AnimatePresence + motion for cinematic effect every session */}
          <AnimatePresence>
            {summary && (
              <motion.div
                key={summary.id}
                className="summary-banner"
                initial={{ opacity: 0, y: 30, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 20, scale: 0.98 }}
                transition={{ duration: 0.55, ease: "easeOut" }}
              >
                <div className="summary-title">✅ Session Summary</div>
                <div className="summary-body">
                  Duration: {summary.duration_s}s • Intercepted: {summary.total_intercepted} • Modified: {summary.total_modified} • Alerts: {summary.total_alerts}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <div className="card">
          <div className="card-head"><strong>Select Flow</strong></div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <select
              value={selectedIndex}
              onChange={(e) => setSelectedIndex(Number(e.target.value))}
              className="preset-select"
            >
              {flows.map((f, i) => (
                <option key={f.id} value={i}>{`#${f.id} ${f.request.method} ${f.request.url.replace(/^https?:\/\//,'')}`}</option>
              ))}
            </select>
            <button className="mitm-btn" onClick={exportSelected} disabled={!selectedFlow}>Export</button>
            <button className="mitm-btn" onClick={() => {
              if (!selectedFlow) return;
              setLogs(prev => [{ id: `replay-${selectedFlow.id}`, t: selectedFlow.t, method: selectedFlow.request.method, url: selectedFlow.request.url, change: "Replayed", alert: selectedFlow.alert }, ...prev].slice(0, 500));
              setFlows(prev => [selectedFlow, ...prev.filter(p => p.id !== selectedFlow.id)].slice(0, capFlows));
              setSelectedIndex(0);
            }} disabled={!selectedFlow}>Replay</button>
          </div>
        </div>

        <div className="card">
          <div className="card-head"><Activity size={16} /> Live Preview</div>
          <div style={{ fontSize: 13, color: "var(--muted)", marginBottom: 8 }}>Newest flow is shown in the panels below. Pick previous flows with the selector.</div>

          {/* Session progress */}
          <div className="session-progress-row">
            <div className="session-progress-label">Session</div>
            <div className="session-progress">
              <div className="session-progress-inner" style={{ width: `${sessionProgress}%` }} />
            </div>
            <div className="session-progress-percent">{sessionProgress}%</div>
          </div>

          <div style={{ marginTop: 8, color: "var(--muted)", fontSize: 13 }}>
            Session length: {sessionDuration}s • Interval: {Math.round(autoInterval)}ms
          </div>
        </div>
      </section>

      {/* 3 panels: Request | Original | Modified */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card mitm-panel">
          <div className="card-head"><strong>📡 Request</strong></div>
          {selectedFlow ? (
            <>
              <div className="text-xs">Method: <span className="font-mono">{selectedFlow.request.method}</span></div>
              <div className="text-xs">URL: <span className="font-mono">{selectedFlow.request.url}</span></div>
              <div style={{ marginTop: 8 }} className="mitm-pre">{safePretty(selectedFlow.request.headers)}</div>
              <div style={{ marginTop: 8 }} className="mitm-pre">{safePretty(selectedFlow.request.body)}</div>
            </>
          ) : <div className="muted">No flow selected</div>}
        </div>

        <div className="card mitm-panel">
          <div className="card-head"><strong>📥 Original Response</strong></div>
          {selectedFlow ? (
            <>
              <div className="text-xs">Status: <span className="font-mono">{selectedFlow.original_response.status}</span></div>
              <div style={{ marginTop: 8 }} className="mitm-pre">{safePretty(selectedFlow.original_response.headers)}</div>
              <div style={{ marginTop: 8 }} className="mitm-pre">{safePretty(selectedFlow.original_response.body)}</div>
            </>
          ) : <div className="muted">No flow selected</div>}
        </div>

        <div className="card mitm-panel">
          <div className="card-head"><strong>⚙️ Modified Response</strong></div>
          {selectedFlow ? (
            <>
              <div className="text-xs">Status: <span className="font-mono">{selectedFlow.modified_response.status}</span></div>
              <div style={{ marginTop: 8 }} className="text-xs mb-1">Notes: {selectedFlow.notes.length ? selectedFlow.notes.join("; ") : "None"}</div>
              <div style={{ marginTop: 8 }} className="mitm-pre">{safePretty(selectedFlow.modified_response.headers)}</div>
              <div style={{ marginTop: 8 }} className="mitm-pre">{safePretty(selectedFlow.modified_response.body)}</div>
              <div style={{ marginTop: 8 }} className="muted">Alert: {selectedFlow.alert || "—"}</div>
            </>
          ) : <div className="muted">No flow selected</div>}
        </div>
      </section>

      {/* Logs area */}
      <section className="logs" style={{ marginTop: 14 }}>
        <div className="logs-head">Interception Log</div>
        <div className="logs-body" ref={logsRef}>
          {logs.length ? (
            <>
              <div className="log-header">
                <div className="log-time">Time</div>
                <div className="log-method">Method</div>
                <div className="log-url">URL</div>
                <div className="log-action">Change</div>
                <div className="log-alert">Alert</div>
              </div>

              {logs.map((l, i) => {
                const isError = !!l.alert;
                const key = `${l.id}-${i}`;
                return (
                  <div
                    key={key}
                    className={`log-row ${isError ? "log-error" : "log-ok"} ${newestLogIdRef.current && String(l.id).startsWith(String(newestLogIdRef.current).split('-')[0]) ? "log-new" : ""}`}
                    onClick={() => {
                      const foundIndex = flows.findIndex(f => f.id === l.id);
                      if (foundIndex !== -1) setSelectedIndex(foundIndex);
                    }}
                    title={l.url}
                  >
                    <div className="log-time">{`t+${Math.round((Date.now()/1000) - l.t)}s`}</div>
                    <div className="log-method">{l.method}</div>
                    <div className="log-url" title={l.url}>{l.url.replace(/^https?:\/\//,'')}</div>
                    <div className="log-action">{l.change}</div>
                    <div className="log-alert">{l.alert || "—"}</div>
                  </div>
                );
              })}
            </>
          ) : (
            <div className="log-empty">No interceptions yet — start the simulation to begin.</div>
          )}
        </div>
      </section>
    </div>
  );
}
