
import React, { useState, useEffect, useRef } from "react";
import IntroAnimation from "./components/IntroAnimation";
import MatrixBackground from "./components/MatrixBackground";
import Navigation from "./components/Navigation";
import ScanConfiguration from "./components/ScanConfiguration";
import VulnerabilitySelection from "./components/VulnerabilitySelection";
import ResultsSummary from "./components/ResultsSummary";
import VulnerabilityResults from "./components/VulnerabilityResults";
import VulnerabilityDetailsModal from "./components/VulnerabilityDetailsModal";
import vulnerabilityTypes from "./data/vulnerabilityTypes";
import "./index.css";

const API_BASE = import.meta?.env?.VITE_API_BASE || "http://localhost:5000";

function App() {
  const [showIntro, setShowIntro] = useState(true);
  const [url, setUrl] = useState("");
  const [selectedVulnerabilities, setSelectedVulnerabilities] = useState([]);
  const [selectAll, setSelectAll] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanComplete, setScanComplete] = useState(false);
  const [scanResults, setScanResults] = useState([]);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentTime, setCurrentTime] = useState("");
  const [currentDate, setCurrentDate] = useState("");
  const [activeTab, setActiveTab] = useState("scan");
  const [showVulnerabilityDetails, setShowVulnerabilityDetails] = useState(null);

  const progressTimerRef = useRef(null);

  // Update time/date display
  useEffect(() => {
    const tick = () => {
      const now = new Date();
      const hh = String(now.getHours()).padStart(2, "0");
      const mm = String(now.getMinutes()).padStart(2, "0");
      const ss = String(now.getSeconds()).padStart(2, "0");
      setCurrentTime(${hh}:${mm}:${ss});

      const month = String(now.getMonth() + 1).padStart(2, "0");
      const day = String(now.getDate()).padStart(2, "0");
      const year = now.getFullYear();
      setCurrentDate(${month}/${day}/${year});
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);

  // Select All controller
  useEffect(() => {
    if (selectAll) {
      setSelectedVulnerabilities(vulnerabilityTypes.map((v) => v.id));
    }
  }, [selectAll]);

  useEffect(() => {
    setSelectAll(selectedVulnerabilities.length === vulnerabilityTypes.length);
  }, [selectedVulnerabilities]);

  const handleVulnerabilityToggle = (id) => {
    setSelectedVulnerabilities((prev) =>
      prev.includes(id) ? prev.filter((v) => v !== id) : [...prev, id]
    );
  };

  const startProgress = () => {
    setScanProgress(0);
    if (progressTimerRef.current) clearInterval(progressTimerRef.current);
    progressTimerRef.current = setInterval(() => {
      setScanProgress((p) => {
        if (p >= 95) return 95; // hang at 95% until backend returns
        return p + Math.floor(Math.random() * 5) + 1;
      });
    }, 250);
  };

  const stopProgress = (finalValue = 100) => {
    if (progressTimerRef.current) {
      clearInterval(progressTimerRef.current);
      progressTimerRef.current = null;
    }
    setScanProgress(finalValue);
  };

  const handleScan = async () => {
    if (!url) return alert("Please enter a URL to scan");
    if (selectedVulnerabilities.length === 0)
      return alert("Please select at least one vulnerability");

    setIsScanning(true);
    setScanComplete(false);
    setActiveTab("scan");
    startProgress();

    try {
      const res = await fetch(${API_BASE}/scan, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, tools: selectedVulnerabilities }),
      });

      const data = await res.json();
      stopProgress(100);
      setScanResults(Array.isArray(data.results) ? data.results : []);
      setScanComplete(true);
      setActiveTab("results");
    } catch (e) {
      console.error(e);
      stopProgress(0);
      alert("Scan failed. Check backend connectivity.");
    } finally {
      setIsScanning(false);
    }
  };

  return showIntro ? (
    <IntroAnimation onComplete={() => setShowIntro(false)} />
  ) : (
    <div className="min-h-screen">
      <MatrixBackground />
      <div className="scanline"></div>

      <Navigation currentTime={currentTime} currentDate={currentDate} />

      <div className="container mx-auto py-8 px-4">
        {/* Tabs */}
        <div className="flex border-b border-gray-700 mb-6">
          <button
            className={`py-2 px-4 font-medium ${
              activeTab === "scan"
                ? "text-green-400 border-b-2 border-green-400"
                : "text-gray-400 hover:text-green-300"
            }`}
            onClick={() => setActiveTab("scan")}
          >
            Scan
          </button>
          <button
            className={`py-2 px-4 font-medium ${
              activeTab === "results"
                ? "text-green-400 border-b-2 border-green-400"
                : "text-gray-400 hover:text-green-300"
            }`}
            onClick={() => setActiveTab("results")}
            disabled={!scanComplete}
            title={!scanComplete ? "Run a scan to see results" : ""}
          >
            Results
          </button>
        </div>

        {activeTab === "scan" && (
          <>
            <ScanConfiguration
              url={url}
              onUrlChange={setUrl}
              onScan={handleScan}
              isScanning={isScanning}
              scanProgress={scanProgress}
              selectedCount={selectedVulnerabilities.length}
            />

            <VulnerabilitySelection
              selectedVulnerabilities={selectedVulnerabilities}
              onToggle={handleVulnerabilityToggle}
              selectAll={selectAll}
              onSelectAll={setSelectAll}
              isScanning={isScanning}
            />
          </>
        )}

        {activeTab === "results" && scanComplete && (
          <>
            <ResultsSummary
              results={scanResults}
              url={url}
              onExport={() =>
                alert("Report exported! (hook your PDF generator here)")
              }
            />

            <VulnerabilityResults
              results={scanResults}
              onViewDetails={setShowVulnerabilityDetails}
            />
          </>
        )}
      </div>

      <VulnerabilityDetailsModal
        vulnerability={showVulnerabilityDetails}
        onClose={() => setShowVulnerabilityDetails(null)}
      />
    </div>
  );
}

export default App;
