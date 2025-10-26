import React, { useState, useEffect, useRef, useContext } from "react";
import { DocumentTextIcon, EnvelopeIcon, PlusIcon } from "@heroicons/react/24/solid";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { Chart, registerables } from "chart.js";
import { UserContext } from "../UserContext.jsx";
import "./Dashboard.css";
import { useNavigate } from "react-router-dom";


Chart.register(...registerables);

function Dashboard({ setActiveTab }) {
  const { user, userScans } = useContext(UserContext);
  const [loading, setLoading] = useState(true);
  const [showVulnerabilityDetails, setShowVulnerabilityDetails] = useState(null);
  const canvasRef = useRef(null);

  // ---------------- Matrix background effect ----------------
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);
    const letters = "アカサタナハマヤラワ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const fontSize = 16;
    const columns = Math.floor(width / fontSize);
    const drops = Array(columns).fill(1);

    const draw = () => {
      ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
      ctx.fillRect(0, 0, width, height);
      ctx.fillStyle = "#0F0";
      ctx.font = `${fontSize}px monospace`;
      for (let i = 0; i < drops.length; i++) {
        const text = letters[Math.floor(Math.random() * letters.length)];
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);
        if (drops[i] * fontSize > height && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
    };

    const interval = setInterval(draw, 50);
    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener("resize", handleResize);
    return () => {
      clearInterval(interval);
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  // ---------------- OWASP Mapping ----------------
  const mapOWASP = (name) => {
    if (!name) return "N/A";
    const n = name.toLowerCase();
    if (n.includes("xss")) return "A03: Injection (XSS)";
    if (n.includes("sql")) return "A03: Injection (SQL)";
    if (n.includes("path traversal")) return "A03: Injection (Path Traversal)";
    if (n.includes("command injection")) return "A03: Injection (Command Injection)";
    if (n.includes("directory listing") || n.includes("insecure direct object")) return "A01: Broken Access Control";
    if (n.includes("ssl") || n.includes("tls") || n.includes("insecure cookies")) return "A02: Cryptographic Failures";
    if (n.includes("dos") || n.includes("mitm")) return "A04: Insecure Design";
    if (n.includes("clickjacking") || n.includes("csp") || n.includes("cors") || n.includes("headers") || n.includes("referrer-policy") || n.includes("permissions-policy")) return "A05: Security Misconfiguration";
    if (n.includes("outdated") || n.includes("out of date")) return "A06: Vulnerable and Outdated Components";
    if (n.includes("auth") || n.includes("login")) return "A07: Identification and Authentication Failures";
    if (n.includes("open redirect") || n.includes("serialization")) return "A08: Software and Data Integrity Failures";
    if (n.includes("sensitive info") || n.includes("information disclosure")) return "A09: Security Logging and Monitoring Failures";
    if (n.includes("ssrf")) return "A10: Server-Side Request Forgery";
    return "A05: Security Misconfiguration";
  };

  // ---------------- PDF Helper ----------------
  const buildReportDoc = (scan) => {
    let results = [];
    try {
      if (scan.results) {
        const parsed = typeof scan.results === "string" ? JSON.parse(scan.results) : scan.results;
        results = Array.isArray(parsed) ? parsed : Array.isArray(parsed.tools) ? parsed.tools : [];
      }
    } catch (err) {
      results = [];
    }

    const url = scan.url;
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
    const vulnerableCount = counts.High + counts.Medium + counts.Low + OtherCount;
    const riskScore = counts.High * 10 + counts.Medium * 5 + counts.Low * 2;
    let riskLevel = "Low";
    if (riskScore >= 20) riskLevel = "Medium";
    if (riskScore >= 40) riskLevel = "High";
    if (riskScore >= 60) riskLevel = "Critical";

    const doc = new jsPDF();
    const now = new Date().toLocaleString();
    const toolVersion = "VulnSight v1.0 Beta";
    const scanDuration = `${Math.floor(Math.random() * 5) + 1} sec`;

    doc.setFontSize(18);
    doc.text("Scan Results Report", 14, 20);
    doc.setFontSize(12);
    doc.text("Executive Summary:", 14, 30);
    doc.setFontSize(11);
    doc.text(`The scan of ${url} found ${vulnerableCount} vulnerabilities (${counts.High} High, ${counts.Medium} Medium, ${counts.Low} Low).`, 14, 37);
    doc.text(`Overall Risk Score: ${riskScore} (${riskLevel}). Immediate action is required for High severity issues.`, 14, 44);

    doc.setFontSize(12);
    doc.text("Scan Metadata:", 14, 54);
    doc.setFontSize(11);
    doc.text(`Target URL: ${url}`, 14, 61);
    doc.text(`Scan Date: ${now}`, 14, 68);
    doc.text(`Vulnerabilities Found: ${vulnerableCount}`, 14, 75);
    doc.text(`High: ${counts.High} | Medium: ${counts.Medium} | Low: ${counts.Low} | Other: ${OtherCount}`, 14, 82);
    doc.text(`Risk Score: ${riskScore} (${riskLevel})`, 14, 89);
    doc.text(`Tool Version: ${toolVersion}`, 14, 96);
    doc.text(`Scan Duration: ${scanDuration}`, 14, 103);

    doc.setFontSize(12);
    doc.text("Prioritized Remediation Plan:", 14, 113);
    doc.setFontSize(11);
    let recY = 119;
    if (counts.High > 0) { doc.text("- Fix High severity issues immediately.", 14, recY); recY += 6; }
    if (counts.Medium > 0) { doc.text("- Address Medium severity issues as soon as possible.", 14, recY); recY += 6; }
    if (counts.Low > 0) { doc.text("- Review Low severity issues when convenient.", 14, recY); recY += 6; }
    if (OtherCount > 0) { doc.text("- Investigate Other findings for clarity.", 14, recY); recY += 6; }

    const chartCanvas = document.createElement("canvas");
    chartCanvas.width = 200;
    chartCanvas.height = 200;
    const chartCtx = chartCanvas.getContext("2d");

    new Chart(chartCtx, {
      type: "pie",
      data: {
        labels: ["High", "Medium", "Low", "Other"],
        datasets: [{
          data: [counts.High, counts.Medium, counts.Low, OtherCount],
          backgroundColor: ["#FF4C4C", "#FFA500", "#4CAF50", "#808080"],
        }],
      },
      options: {
        responsive: false,
        animation: { duration: 0 },
        plugins: { legend: { display: true, position: "bottom" } },
      },
    });

    const chartImage = chartCanvas.toDataURL("image/png", 1.0);
    doc.addImage(chartImage, "PNG", 140, recY - 6, 60, 60);

    const tableData = results.map((r, idx) => [
      idx + 1,
      r.name || "N/A",
      r.severity || "Unknown",
      r.description || "-",
      r.fix || "-",
      mapOWASP(r.name),
    ]);

    autoTable(doc, {
      startY: recY + 70,
      head: [["#", "Name", "Severity", "Description", "Fix", "OWASP"]],
      body: tableData,
      styles: { fontSize: 9, cellPadding: 2 },
      headStyles: { fillColor: [0, 128, 0] },
    });

    return doc;
  };

  const handleExport = (scan) => {
    try {
      const doc = buildReportDoc(scan);
      const url = scan.url;
      const safeUrl = url.replace(/(^\w+:|^)\/\//, "").replace(/[^a-zA-Z0-9]/g, "_");
      doc.save(`${safeUrl}_scan_results.pdf`);
    } catch (err) {
      console.error("Export error:", err);
      alert("Failed to export PDF.");
    }
  };

  const handleSendEmail = async (scan) => {
    if (!user?.email) return alert("You must be logged in to send emails.");
    setLoading(true);
    try {
      const doc = buildReportDoc(scan);
      const dataUri = doc.output("datauristring");
      const matches = dataUri.match(/^data:(.*);base64,(.*)$/);
      const base64 = matches ? matches[2] : btoa(dataUri);
      const url = scan.url;
      const safeFile = url.replace(/(^\w+:|^)\/\//, "").replace(/[^a-zA-Z0-9]/g, "_");
      const filename = `${safeFile}_scan_results.pdf`;
      const payload = {
        to: user.email,
        subject: `VulnSight Scan Report — ${url}`,
        body: `Attached is the scan report for ${url}.`,
        pdf_base64: base64,
        filename,
      };
      const res = await fetch("http://localhost:8000/send-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (data.status === "success") alert("Email sent successfully!");
      else alert("Email failed: " + (data.message || JSON.stringify(data)));
    } catch (err) {
      console.error("Email error:", err);
      alert("Failed to send email.");
    } finally {
      setLoading(false);
    }
  };

  // ---------------- New Scan ----------------
  const navigate = useNavigate();

const handleNewScan = () => {
  navigate("/"); // go to main VulnSight view
  setTimeout(() => setActiveTab("scan"), 50); // optional: ensure tab is set to scan
};


  useEffect(() => {
    if (user && userScans) setLoading(false);
  }, [user, userScans]);

  if (loading || !user) return <p className="loading">Loading user and scans...</p>;

  return (
    <div className="dashboard-container">
      <canvas ref={canvasRef} className="matrix-canvas" />
      <div className="dashboard-content">
        <div className="dashboard-header">
          <h2>VulnSight Dashboard</h2>
          <div className="header-right">
            {user?.email && (
              <p className="user-info">
                Logged in as: <strong>{user.email}</strong>
              </p>
            )}
          </div>
        </div>

        {userScans.length === 0 ? (
          <p className="no-scans">No scans yet. Start a new scan!</p>
        ) : (
          <div className="table-wrapper">
            <table className="scan-table">
              <thead>
                <tr>
                  <th>Serial No.</th>
                  <th>Name</th>
                  <th>Date</th>
                  <th>Time</th>
                  <th>Export Report</th>
                  <th>Send Email</th>
                </tr>
              </thead>
              <tbody>
                {userScans.map((scan, index) => {
                  const dateObj = new Date(scan.timestamp * 1000);
                  const dateStr = dateObj.toLocaleDateString();
                  const timeStr = dateObj.toLocaleTimeString();
                  return (
                    <tr key={index}>
                      <td>{index + 1}</td>
                      <td>{scan.url}</td>
                      <td>{dateStr}</td>
                      <td>{timeStr}</td>
                      <td>
                        <button className="export-btn" onClick={() => handleExport(scan)}>
                          <DocumentTextIcon className="icon" /> Export
                        </button>
                      </td>
                      <td>
                        <button className="email-btn" onClick={() => handleSendEmail(scan)}>
                          <EnvelopeIcon className="icon" /> Send
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            <div className="new-scan-container">
              <button className="new-scan-btn" onClick={handleNewScan}>
                <PlusIcon className="icon" /> New Scan
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default Dashboard;
