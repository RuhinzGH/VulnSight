import React, { useContext } from "react";
import { FaExclamationTriangle, FaExclamationCircle, FaInfoCircle } from "react-icons/fa";
import { useNavigate } from "react-router-dom";
import "./resultsSummary.css";

import { UserContext } from "../UserContext.jsx"; // ✅ import context

function ResultsSummary({ results, url }) {
  const navigate = useNavigate();
  const { user } = useContext(UserContext); // ✅ get user

  if (!results || results.length === 0) {
    return <div className="summary-empty">No results to display.</div>;
  }

  const counts = {
    High: results.filter((r) => r.severity?.toLowerCase() === "high").length,
    Medium: results.filter((r) => r.severity?.toLowerCase() === "medium").length,
    Low: results.filter((r) => r.severity?.toLowerCase() === "low").length,
  };

  const OtherCount = results.reduce((acc, r) => {
    const s = (r.severity || "unknown").toLowerCase();
    if (!["high", "medium", "low"].includes(s)) acc++;
    return acc;
  }, 0);

  const vulnerableCount = results.filter((r) =>
    ["high", "medium", "low"].includes((r.severity || "").toLowerCase())
  ).length;

  const riskScore = counts.High * 10 + counts.Medium * 5 + counts.Low * 2;
  let riskLevel = "Low";
  if (riskScore >= 20) riskLevel = "Medium";
  if (riskScore >= 40) riskLevel = "High";
  if (riskScore >= 60) riskLevel = "Critical";

  return (
    <div className="summary-container">
      <div className="summary-header">
        <div>
          <h2 className="summary-title">Scan Results</h2>
          <p className="summary-url">
            Target: <span>{url}</span>
          </p>
          {vulnerableCount > 0 ? (
            <p className="summary-vuln-count">{vulnerableCount} vulnerabilities found</p>
          ) : (
            <p className="summary-vuln-count safe">No vulnerabilities found 🎉</p>
          )}
          <p className="summary-risk">
            Risk Score: {riskScore} ({riskLevel})
          </p>
        </div>

        {/* ✅ Conditional button */}
        {user ? (
          <button className="export-btn info-btn" onClick={() => navigate("/dashboard")}>
            <FaInfoCircle className="export-icon" />
            <span>Go to Dashboard</span>
          </button>
        ) : (
          <button className="export-btn info-btn" onClick={() => navigate("/login")}>
            <FaInfoCircle className="export-icon" />
            <span>Sign in to save your scans</span>
          </button>
        )}
      </div>

      <div className="summary-counts">
        <div className="count-card high">
          <div>
            <p>High</p>
            <h3>{counts.High}</h3>
          </div>
          <FaExclamationTriangle className="count-icon" />
        </div>

        <div className="count-card medium">
          <div>
            <p>Medium</p>
            <h3>{counts.Medium}</h3>
          </div>
          <FaExclamationCircle className="count-icon" />
        </div>

        <div className="count-card low">
          <div>
            <p>Low</p>
            <h3>{counts.Low}</h3>
          </div>
          <FaExclamationCircle className="count-icon" />
        </div>

        {OtherCount > 0 && (
          <div className="count-card other">
            <div>
              <p>Other</p>
              <h3>{OtherCount}</h3>
            </div>
            <FaExclamationCircle className="count-icon" />
          </div>
        )}
      </div>
    </div>
  );
}

export default ResultsSummary;
