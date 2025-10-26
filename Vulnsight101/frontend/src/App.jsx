import React, { useState, useEffect, useRef, useContext } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from "react-router-dom";
import ReactMarkdown from "react-markdown";

import IntroAnimation from "./Components/IntroAnimation";
import MatrixBackground from "./Components/MatrixBackground";
import Navigation from "./Components/Navigation";
import ScanConfiguration from "./Components/ScanConfiguration";
import VulnerabilitySelection from "./Components/VulnerabilitySelection";
import ResultsSummary from "./Components/ResultsSummary";
import VulnerabilityResults from "./Components/VulnerabilityResults";
import VulnerabilityDetailsModal from "./Components/VulnerabilityDetailsModal";
import vulnerabilityTypes from "./data/vulnerabilityTypes";
import Login from "./Components/Login";
import Dashboard from "./Components/Dashboard";
import DoSSimulation from "./Components/DoSSimulation";
import MITMSimulation from "./Components/MITMReplay";
import sampleFlows from "./data/sample_mitm_flows.json";

import { UserContext } from "./UserContext.jsx";

import "./index.css";
import "./components/Navigation.css";
import "./components/Login.css";
import "./Overrides.css";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

// ---------------- Navigation Wrapper ----------------
function NavigationWrapper({ currentTime, currentDate }) {
  const navigate = useNavigate();
  return (
    <div className="sticky-nav">
      <Navigation currentTime={currentTime} currentDate={currentDate} navigate={navigate} />
    </div>
  );
}

// ---------------- App Component ----------------
function App() {
  const [showIntro, setShowIntro] = useState(true);
  const [url, setUrl] = useState("");
  const [selectedVulnerabilities, setSelectedVulnerabilities] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState({ target: "", vulnerabilities: [], llm_summary: null, raw: null });
  const [scanProgress, setScanProgress] = useState(0);
  const [currentTime, setCurrentTime] = useState("");
  const [currentDate, setCurrentDate] = useState("");
  const [activeTab, setActiveTab] = useState("scan");
  const [showVulnerabilityDetails, setShowVulnerabilityDetails] = useState(null);

  const progressTimerRef = useRef(null);
  const scanRef = useRef(null);
  const resultsRef = useRef(null);
  const [sliderStyle, setSliderStyle] = useState({});

  const { user, addScan } = useContext(UserContext);

  // ---------------- Clock ----------------
  useEffect(() => {
    const tick = () => {
      const now = new Date();
      setCurrentTime(
        `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(
          now.getSeconds()
        ).padStart(2, "0")}`
      );
      setCurrentDate(
        `${String(now.getMonth() + 1).padStart(2, "0")}/${String(now.getDate()).padStart(2, "0")}/${now.getFullYear()}`
      );
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);

  // ---------------- Tab Slider ----------------
  useEffect(() => {
    const activeRef = activeTab === "scan" ? scanRef : resultsRef;
    if (activeRef.current) {
      setSliderStyle({
        left: activeRef.current.offsetLeft,
        width: activeRef.current.offsetWidth,
      });
    }
  }, [activeTab]);

  // ---------------- Vulnerability Selection ----------------
  const handleVulnerabilityToggle = (id) => {
    setSelectedVulnerabilities((prev) =>
      prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]
    );
  };
  const handleSelectAllToggle = (shouldSelectAll) => {
    setSelectedVulnerabilities(shouldSelectAll ? vulnerabilityTypes.map((v) => v.id) : []);
  };
  const selectAll = selectedVulnerabilities.length === vulnerabilityTypes.length;

  // ---------------- Progress ----------------
  const startProgress = () => {
    setScanProgress(0);
    if (progressTimerRef.current) clearInterval(progressTimerRef.current);
    progressTimerRef.current = setInterval(() => {
      setScanProgress((p) => Math.min(p + Math.floor(Math.random() * 5) + 1, 95));
    }, 250);
  };
  const stopProgress = (finalValue = 100) => {
    if (progressTimerRef.current) {
      clearInterval(progressTimerRef.current);
      progressTimerRef.current = null;
    }
    setScanProgress(finalValue);
  };

  // ---------------- Scan Handlers ----------------
  const handleScan = async () => {
    if (!url) return alert("Please enter a URL");
    if (selectedVulnerabilities.length === 0) return alert("Select at least one vulnerability");

    setIsScanning(true);
    setScanResults({ target: "", vulnerabilities: [], llm_summary: null, raw: null });
    setActiveTab("scan");
    startProgress();

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
      const data = await res.json();

      // Pass full backend data including LLM summary
      const normalized = {
        target: data.results?.target || data.url || url,
        vulnerabilities: data.results || [],
        llm_summary: data.llm_summary || null,
        raw: data,
      };

      handleScanComplete(normalized);
    } catch (err) {
      console.error("Scan failed:", err);
      stopProgress(100);
      setIsScanning(false);
      setScanResults({
        target: url,
        vulnerabilities: [
          {
            id: "error",
            name: "Scan Error",
            severity: "Unknown",
            description: err.message,
            fix: "Check backend service",
          },
        ],
        llm_summary: null,
        raw: null,
      });
      setActiveTab("results");
    }
  };

  const handleScanComplete = (normalizedData) => {
    stopProgress(100);
    setScanResults(normalizedData);
    setIsScanning(false);
    setActiveTab("results");

    if (user) {
      const dashboardScan = {
        url: normalizedData.target,
        results: normalizedData.vulnerabilities,
        timestamp: Math.floor(Date.now() / 1000),
      };
      addScan(dashboardScan);
    }
  };

  // ---------------- Intro ----------------
  if (showIntro) {
    return <IntroAnimation onComplete={() => setShowIntro(false)} />;
  }

  // ---------------- Render ----------------
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/dashboard" element={user ? <Dashboard setActiveTab={setActiveTab} /> : <Navigate to="/login" />} />
        <Route path="/navigation" element={<NavigationWrapper currentTime={currentTime} currentDate={currentDate} />} />

        <Route
          path="/"
          element={
            <div className="main-page-container">
              <MatrixBackground />
              <div className="scanline"></div>

              {/* Sticky Navigation */}
              <NavigationWrapper currentTime={currentTime} currentDate={currentDate} />

              {/* Page Content Below Navbar */}
              <div className="page-content container mx-auto py-8 px-4 max-w-md">
                <div className="tab-container relative flex mb-6">
                  <div
                    className="tab-slider absolute bottom-0 h-0.5 bg-white transition-all duration-300 ease-in-out"
                    style={sliderStyle}
                  />
                  <button
                    ref={scanRef}
                    className={`tab-button font-bold ${activeTab === "scan" ? "active" : ""}`}
                    onClick={() => setActiveTab("scan")}
                  >
                    Scan
                  </button>
                  <button
                    ref={resultsRef}
                    className={`tab-button font-bold ${activeTab === "results" ? "active" : ""}`}
                    onClick={() => setActiveTab("results")}
                  >
                    Results
                  </button>
                </div>

                {activeTab === "scan" && (
                  <>
                    <ScanConfiguration
                      url={url}
                      onUrlChange={setUrl}
                      selectedVulnerabilities={selectedVulnerabilities}
                      onScanComplete={handleScanComplete}
                      API_BASE={API_BASE}
                    />
                    <VulnerabilitySelection
                      selectedVulnerabilities={selectedVulnerabilities}
                      onToggle={handleVulnerabilityToggle}
                      selectAll={selectAll}
                      onSelectAll={handleSelectAllToggle}
                      isScanning={isScanning}
                    />
                  </>
                )}

                {activeTab === "results" && (
                  <>
                    {scanResults.vulnerabilities?.length > 0 ? (
                      <>
                        <ResultsSummary results={scanResults.vulnerabilities} url={scanResults.target || url} />
                        <VulnerabilityResults
                          results={scanResults.vulnerabilities}
                          onViewDetails={setShowVulnerabilityDetails}
                        />

                        {/* ---- AI Summary Card ---- */}
                        {scanResults.llm_summary && (
                          <div className="ai-summary-card mt-4">
                            <h2>AI Summary</h2>
                            <ReactMarkdown>
                              {typeof scanResults.llm_summary === "string"
                                ? scanResults.llm_summary
                                : scanResults.llm_summary.explanation ||
                                  JSON.stringify(scanResults.llm_summary, null, 2)}
                            </ReactMarkdown>
                          </div>
                        )}
                      </>
                    ) : (
                      <div className="bg-black/70 border border-green-700 rounded-xl p-6 text-green-400 text-center">
                        <p className="text-sm text-gray-400">
                          No scan results yet. Run a scan to see vulnerabilities.
                        </p>
                      </div>
                    )}
                  </>
                )}
              </div>

              <VulnerabilityDetailsModal
                vulnerability={showVulnerabilityDetails}
                onClose={() => setShowVulnerabilityDetails(null)}
              />
            </div>
          }
        />
        <Route path="/simulation/mitm" element={<MITMSimulation flowData={sampleFlows} />} />
        <Route path="/simulation/dos" element={<DoSSimulation />} />
        <Route path="/simulation/mitm" element={<MITMSimulation />} />
      </Routes>
    </Router>
  );
}

export default App;
