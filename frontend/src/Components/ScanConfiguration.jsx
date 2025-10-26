import React, { useState, useContext, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { FaInfoCircle } from "react-icons/fa";
import "./ScanConfiguration.css";
import { UserContext } from "../UserContext.jsx";

function ScanConfiguration({
  url,
  onUrlChange,
  selectedVulnerabilities,
  onScanComplete,
  API_BASE,
}) {
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [estimatedTime, setEstimatedTime] = useState("~10s");
  const navigate = useNavigate();
  const { user } = useContext(UserContext);
  const progressRef = useRef(0); // ⚡ avoid re-render lag

  // ---------------- Normalize results ----------------
  const normalizeResults = (backendData) => {
    if (!backendData) return { target: url, vulnerabilities: [] };

    // Keep full raw data for each vulnerability
    return {
      target: backendData.url || backendData.target || url,
      vulnerabilities: (backendData.results || []).map((vuln, idx) => ({
        ...vuln, // preserve all fields
        id: vuln.id || idx,
        name: vuln.name || vuln.type || `Unnamed Vulnerability #${idx + 1}`,
        severity: vuln.severity || vuln.level || "Unknown",
        description: vuln.description || vuln.message || "No description provided.",
        fix: vuln.fix || vuln.recommendation || "No fix recommendation available.",
        references: vuln.references || [
          "OWASP Vulnerability Prevention",
          "CWE Reference",
          "NIST Guidelines",
        ],
      })),
      // Optionally keep LLM summaries or extra fields
      llm_summary: backendData.llm_summary || null,
      scan_id: backendData.scan_id || null,
      status: backendData.status || null,
      raw: backendData, // keep full raw response just in case
    };
  };

  // ---------------- Scan handler ----------------
  const handleScan = async () => {
    if (!url.trim()) {
      alert("Please enter a URL to scan");
      return;
    }

    if (!selectedVulnerabilities.length) {
      alert("Please select at least one vulnerability");
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    progressRef.current = 0;

    let finalData = null;
    const startTime = Date.now();
    const totalDuration = 10000; // pretend scan lasts ~10s

    // Progress simulation up to 85%
    const progressInterval = setInterval(() => {
      if (progressRef.current < 85) {
        const elapsed = Date.now() - startTime;
        const estRemaining = Math.max(((totalDuration - elapsed) / 1000).toFixed(0), 1);
        setEstimatedTime(`~${estRemaining}s`);
        const nextVal = Math.min(progressRef.current + 1 + Math.random() * 2, 85);
        progressRef.current = nextVal;
        setScanProgress(nextVal);
      }
    }, 100);

    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          url,
          vulnerabilities: selectedVulnerabilities,
        }),
      });

      if (!res.ok) throw new Error(`Server responded with ${res.status}`);

      const rawData = await res.json();
      finalData = normalizeResults(rawData);

      // Jump to 100% on success
      clearInterval(progressInterval);
      const jumpInterval = setInterval(() => {
        if (progressRef.current >= 100) {
          clearInterval(jumpInterval);
          setIsScanning(false);
          if (onScanComplete) onScanComplete(finalData);
        } else {
          progressRef.current += 3;
          setScanProgress(progressRef.current);
        }
      }, 40);
    } catch (error) {
      console.error("Scan failed:", error);
      clearInterval(progressInterval);

      const fallback = {
        target: url,
        vulnerabilities: [
          {
            name: "Scan Error",
            severity: "Unknown",
            description: error.message,
            fix: "Check backend service",
            references: [],
          },
        ],
        status: "error",
      };

      setIsScanning(false);
      setScanProgress(100);
      if (onScanComplete) onScanComplete(fallback);
    }
  };

  return (
    <div className="scan-card">
      <div className="matrix-overlay"></div>

      {/* Top-right button */}
      <div className="scan-top-right-btn">
        {user ? (
          <button
            className="export-btn info-btn"
            onClick={() => navigate("/dashboard")}
          >
            <FaInfoCircle className="export-icon" />
            <span>Go to Dashboard</span>
          </button>
        ) : (
          <button
            className="export-btn info-btn"
            onClick={() => navigate("/login")}
          >
            <FaInfoCircle className="export-icon" />
            <span>Sign in to save your scans</span>
          </button>
        )}
      </div>

      <h2 className="scan-header">Target Configuration</h2>

      {/* URL Input */}
      <div className="scan-input-group">
        <label className="scan-label">Target URL</label>
        <div className="scan-input-container">
          <input
            type="text"
            className="scan-input url-input-text-white"
            placeholder="Enter URL to scan"
            value={url}
            onChange={(e) => onUrlChange(e.target.value)}
            disabled={isScanning}
          />
          <button
            className={`start-scan-button ${isScanning ? "disabled" : ""}`}
            onClick={handleScan}
            disabled={isScanning}
          >
            {isScanning ? (
              <>
                <svg
                  className="spinner"
                  xmlns="http://www.w3.org/2000/svg"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    className="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    strokeWidth="4"
                  ></circle>
                  <path
                    className="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8v4l3-3-3-3v4a8 8 0 100 16v-4l-3 3 3 3v-4a8 8 0 01-8-8z"
                  ></path>
                </svg>
                Scanning...
              </>
            ) : (
              "Start Scan"
            )}
          </button>
        </div>
      </div>

      {/* Progress Section */}
      {isScanning && (
        <div className="scan-progress-wrapper">
          <div className="scan-progress-text">
            <span>
              Scanning in progress... <span className="time-text">{estimatedTime}</span>
            </span>
            <span>{Math.round(scanProgress)}%</span>
          </div>

          <div className="scan-progress-bar">
            <div
              className="scan-progress-fill"
              style={{ width: `${Math.min(scanProgress, 100)}%` }}
            ></div>
          </div>

          <div className="scan-progress-desc">
            {selectedVulnerabilities.length} vulnerability checks selected
          </div>
        </div>
      )}
    </div>
  );
}

export default ScanConfiguration;
