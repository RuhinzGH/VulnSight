// DoSSimulation.jsx
import "./DoSSimulation.css";
import React, { useState, useRef, useEffect } from "react";
import { Line } from "react-chartjs-2";
import { saveAs } from "file-saver";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";
import {
  Play,
  Square,
  CheckCircle,
  Download,
  Cpu,
  Clock,
  Zap,
  Sliders,
  Activity,
  AlertTriangle,
  Server,
} from "lucide-react";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler);

/*
  Ethical sandbox notes:
  - This component SIMULATES request events locally — it does NOT perform network traffic.
  - Each "request" is a generated object: {id, t, lat, status}
  - Stop = immediate halt (no finalize)
  - Finish = finalize results & call onComplete
*/

export default function DoSSimulation({
  rps: initialRps = 120,
  duration: initialDuration = 12,
  onComplete,
  autoCloseOnComplete = false,
}) {
  // parameters / state
  const [rps, setRps] = useState(initialRps);
  const [duration, setDuration] = useState(initialDuration);
  const [preset, setPreset] = useState("custom");
  const [running, setRunning] = useState(false);
  const [timeElapsed, setTimeElapsed] = useState(0);
  const [dataPoints, setDataPoints] = useState([]); // for chart {t, rps}
  const [logs, setLogs] = useState([]); // rolling logs of simulated requests
  const [counters, setCounters] = useState({ sent: 0, success: 0, error: 0 });
  const [severity, setSeverity] = useState("UNKNOWN");

  const intervalRef = useRef(null);
  const requestIdRef = useRef(0);

  const PRESETS = {
    light: { rps: 50, duration: 10 },
    moderate: { rps: 300, duration: 12 },
    heavy: { rps: 900, duration: 15 },
  };

  // cleanup
  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  // apply preset changes
  useEffect(() => {
    if (preset !== "custom" && PRESETS[preset]) {
      setRps(PRESETS[preset].rps);
      setDuration(PRESETS[preset].duration);
    }
  }, [preset]);

  // build chart dataset
  const chartData = {
    labels: dataPoints.map((d) => d.t),
    datasets: [
      {
        label: "Simulated RPS",
        data: dataPoints.map((d) => d.rps),
        fill: true,
        tension: 0.35,
        pointRadius: 0,
        borderWidth: 2.2,
        backgroundColor: function (context) {
          const { ctx, chartArea } = context.chart;
          if (!chartArea) return "rgba(56,189,248,0.12)";
          const gradient = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
          gradient.addColorStop(0, "rgba(124,58,237,0.6)");
          gradient.addColorStop(1, "rgba(56,189,248,0.08)");
          return gradient;
        },
        borderColor: "#7c3aed",
      },
    ],
  };

  // compute avg rps and severity
  useEffect(() => {
    if (!dataPoints.length) {
      setSeverity("UNKNOWN");
      return;
    }
    const avg = dataPoints.reduce((s, d) => s + d.rps, 0) / dataPoints.length;
    const sev = avg > 1200 ? "HIGH" : avg > 600 ? "MEDIUM" : "LOW";
    setSeverity(sev);
  }, [dataPoints]);

  // MAIN simulation tick executed every second when running
  const step = () => {
    // simulate the "observed RPS" with some variance
    const low = Math.max(1, Math.floor(rps * 0.75));
    const high = Math.max(low + 1, Math.floor(rps * 1.25));
    const simulatedRps = Math.floor(Math.random() * (high - low + 1)) + low;

    // Append datapoint for chart
    setDataPoints((prev) => [...prev, { t: timeElapsed + 1, rps: simulatedRps }]);

    // Simulate per-second requests (but generate them as log entries, not real requests)
    // We'll generate `simulatedRps` lightweight log entries but cap to avoid UI freeze
    const capPerSecond = Math.min(simulatedRps, 200); // UI-friendly cap
    const perRequestChanceOfError = simulatedRps > 800 ? 0.08 : simulatedRps > 400 ? 0.04 : 0.01;

    let sent = 0,
      success = 0,
      error = 0;
    const newLogs = [];

    for (let i = 0; i < capPerSecond; i++) {
      requestIdRef.current += 1;
      const id = requestIdRef.current;
      const lat = Math.max(10, Math.round(randomBetween(10, Math.min(2000, Math.round(1500 * (1 + Math.random()))))));
      const isError = Math.random() < perRequestChanceOfError;
      const status = isError ? randomChoice([500, 502, 503, 504]) : randomChoice([200, 200, 200, 201, 204]);
      const log = {
        id,
        t: timeElapsed + 1,
        lat,
        status,
        msg: isError ? "Simulated server error" : "OK",
      };
      newLogs.push(log);
      sent += 1;
      if (isError) error += 1;
      else success += 1;
    }

    // UI state updates
    setLogs((prev) => {
      const merged = [...newLogs.reverse(), ...prev]; // newest first
      return merged.slice(0, 500); // keep log length bounded
    });
    setCounters((prev) => ({
      sent: prev.sent + sent,
      success: prev.success + success,
      error: prev.error + error,
    }));

    // time + check finalize
    setTimeElapsed((t) => {
      const newT = t + 1;
      if (newT >= duration) {
        // finalize with the points we've collected (stop will be called inside finalize)
        // Use functional state to ensure latest dp snapshot
        setTimeout(() => finalize(), 0);
      }
      return newT;
    });
  };

  // helpers
  const randomBetween = (a, b) => Math.random() * (b - a) + a;
  const randomChoice = (arr) => arr[Math.floor(Math.random() * arr.length)];

  // Start simulation
  const start = () => {
    if (running) return;
    // reset states
    setDataPoints([]);
    setTimeElapsed(0);
    setLogs([]);
    setCounters({ sent: 0, success: 0, error: 0 });
    setSeverity("UNKNOWN");
    setRunning(true);

    // interval every 1 second
    intervalRef.current = setInterval(step, 1000);
  };

  // Stop (emergency halt) - does NOT call finalize, preserves logs, allows resume
  const stop = () => {
    if (!running) return;
    const confirmStop = window.confirm(
      "Stop will immediately halt the simulation. This will NOT finalize results. Continue?"
    );
    if (!confirmStop) return;
    if (intervalRef.current) clearInterval(intervalRef.current);
    intervalRef.current = null;
    setRunning(false);
  };

  // Finalize: compute summary, stop, call onComplete
  const finalize = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
      setRunning(false);
    }
    const points = dataPoints.length ? dataPoints : [];
    const avg = points.length ? points.reduce((s, d) => s + d.rps, 0) / points.length : 0;
    const sev = avg > 1200 ? "HIGH" : avg > 600 ? "MEDIUM" : "LOW";

    const summary = {
      timestamp: new Date().toISOString(),
      parameters: { rps, duration, preset },
      avg_rps: Number(avg.toFixed(2)),
      severity: sev,
      counters,
      data_points: points,
      notes: ["SAFE SIMULATION — no external traffic. All events are generated locally."],
    };

    onComplete && onComplete(summary);

    if (autoCloseOnComplete) {
      // intentionally nothing heavy; just hint to UI
      // you can hook onComplete to close modal or similar
    }
  };

  // Export handlers
  const exportJSON = () => {
    if (!dataPoints.length) return alert("Run simulation first.");
    const payload = {
      exported_at: new Date().toISOString(),
      parameters: { rps, duration, preset },
      counters,
      data_points: dataPoints,
      logs: logs.slice(0, 200), // don't dump huge logs
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    saveAs(blob, `dos_simulation_${Date.now()}.json`);
  };

  const exportCSV = () => {
    if (!dataPoints.length) return alert("Run simulation first.");
    let csv = "time_sec,rps\n";
    dataPoints.forEach((d) => (csv += `${d.t},${d.rps}\n`));
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    saveAs(blob, `dos_simulation_${Date.now()}.csv`);
  };

  const avgRps = dataPoints.length ? (dataPoints.reduce((s, d) => s + d.rps, 0) / dataPoints.length).toFixed(1) : "—";
  const percentComplete = Math.min(100, Math.round((timeElapsed / Math.max(1, duration)) * 100));

  return (
    <div className="dos-dashboard-sandbox">
      <header className="dd-header">
        <div className="left">
          <h2 className="title neon"> <Activity size={20} /> DoS Simulation (Sandbox)</h2>
          <div className="subtitle">Local-only simulated traffic • Safe for demos & labs</div>
        </div>

        <div className="right">
          <div className={`indicator ${running ? "live" : "idle"}`}>
            <span className="dot" />
            <span>{running ? "Running" : "Idle"}</span>
          </div>
        </div>
      </header>

      {/* Chart full width */}
      <section className="chart-full">
        <Line data={chartData} options={{ responsive: true, maintainAspectRatio: false }} />
      </section>

      {/* Controls grid */}
      <section className="grid-controls">
        {/* Column A: Presets & info */}
        <div className="card">
          <div className="card-head"><Zap size={16}/> Preset</div>
          <div className="preset-row">
            {["light", "moderate", "heavy", "custom"].map((p) => (
              <button
                key={p}
                className={`preset-btn ${preset === p ? "active" : ""}`}
                onClick={() => setPreset(p)}
                disabled={running}
              >
                {p.toUpperCase()}
              </button>
            ))}
          </div>

          <div className="card-head small"><Server size={14}/> Parameters</div>
          <div className="param-row">
            <label>RPS</label>
            <input
              type="range"
              min="1"
              max="2000"
              value={rps}
              disabled={running}
              onChange={(e) => {
                setRps(Number(e.target.value));
                setPreset("custom");
              }}
            />
            <div className="param-value">{rps} rps</div>
          </div>

          <div className="param-row">
            <label>Duration (s)</label>
            <input
              type="number"
              min="1"
              max="600"
              value={duration}
              disabled={running}
              onChange={(e) => {
                setDuration(Number(e.target.value));
                setPreset("custom");
              }}
            />
          </div>
        </div>

        {/* Column B: Controls */}
        <div className="card">
          <div className="card-head"><Cpu size={16}/> Controls</div>

          <div className="control-buttons">
            <button className="action start" disabled={running} onClick={start}>
              <Play size={14}/> Start
            </button>
            <button className="action stop" disabled={!running} onClick={stop}>
              <Square size={14}/> Stop
            </button>
            <button
              className="action finish"
              disabled={(!dataPoints.length && !logs.length) || running}
              onClick={() => finalize()}
            >
              <CheckCircle size={14}/> Finish
            </button>
          </div>

          <div className="card-foot">
            <button className="export" onClick={exportJSON} disabled={!dataPoints.length}>
              <Download size={14}/> Export JSON
            </button>
            <button className="export" onClick={exportCSV} disabled={!dataPoints.length}>
              <Download size={14}/> Export CSV
            </button>
          </div>

          <div className="progress-row">
            <div className="progress-label">Progress</div>
            <div className="progress-bar">
              <div className="progress-inner" style={{ width: `${percentComplete}%` }} />
            </div>
            <div className="progress-percent">{percentComplete}%</div>
          </div>
        </div>

        {/* Column C: Live stats & severity */}
        <div className="card">
          <div className="card-head"><Clock size={16}/> Live Stats</div>
          <div className="stats-grid">
            <div className="stat-pill">
              <div className="stat-label">Elapsed</div>
              <div className="stat-value">{timeElapsed}s</div>
            </div>

            <div className="stat-pill">
              <div className="stat-label">Avg RPS</div>
              <div className="stat-value">{avgRps}</div>
            </div>

            <div className="stat-pill">
              <div className="stat-label">Sent</div>
              <div className="stat-value">{counters.sent}</div>
            </div>

            <div className="stat-pill">
              <div className="stat-label">Success</div>
              <div className="stat-value success">{counters.success}</div>
            </div>

            <div className="stat-pill">
              <div className="stat-label">Errors</div>
              <div className="stat-value error">{counters.error}</div>
            </div>

            <div className="stat-pill severity">
              <div className="stat-label">Severity</div>
              <div className={`stat-value severity-${severity.toLowerCase()}`}>{severity}</div>
            </div>
          </div>

          <div className="card-head small"><AlertTriangle size={14}/> Sandbox Warning</div>
          <div className="muted">
            This interface is purely a **local simulation** — no external traffic is generated. Use for demos & teaching only.
          </div>
        </div>
      </section>

   {/* Logs */}
<section className="logs">
  <div className="logs-head">Live Request Log</div>
  <div className="logs-body">
    {logs.length ? (
      <>
        {/* ✅ Added column headers */}
        <div className="log-header">
          <div className="log-time">⏱ Time</div>
          <div className="log-id"># ID</div>
          <div className="log-status">Status</div>
          <div className="log-lat">Latency</div>
          <div className="log-msg">Result</div>
        </div>

        {logs.slice(0, 100).map((l) => (
          <div key={l.id} className={`log-row ${l.status >= 500 ? "log-error" : "log-ok"}`}>
            <div className="log-time">t+{l.t}s</div>
            <div className="log-id">#{l.id}</div>
            <div className="log-status">{l.status}</div>
            <div className="log-lat">{l.lat}ms</div>
            <div className="log-msg">{l.msg}</div>
          </div>
        ))}
      </>
    ) : (
      <div className="log-empty">No logs yet — start the simulation to see entries.</div>
    )}
  </div>
</section>

    </div>
  );
}
