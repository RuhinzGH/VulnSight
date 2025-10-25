import React, { useState } from "react";
import VulnerabilitySelection from "./VulnerabilitySelection";
import VulnerabilityResults from "./VulnerabilityResults";

function VulnScanner() {
  // --- State Management ---
  const [selectedVulnerabilities, setSelectedVulnerabilities] = useState([]);
  const [scanResults, setScanResults] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [viewResults, setViewResults] = useState(false);

  // --- Select/Deselect vulnerabilities ---
  const toggleVulnerability = (vuln) => {
    setSelectedVulnerabilities((prev) =>
      prev.includes(vuln)
        ? prev.filter((v) => v !== vuln)
        : [...prev, vuln]
    );
  };

  // --- Select All ---
  const selectAll = (vulnList) => {
    setSelectedVulnerabilities((prev) =>
      prev.length === vulnList.length ? [] : vulnList
    );
  };

  // --- Handle Scan ---
  const handleScan = async (results) => {
    // Called when VulnerabilitySelection finishes scanning
    setScanResults(results);
    setViewResults(true); // Automatically switch to results screen
  };

  // --- Reset / Go Back ---
  const handleBack = () => {
    setViewResults(false);
    setScanResults(null);
    setIsScanning(false);
  };

  return (
    <div className="container mx-auto p-6">
      {!viewResults ? (
        <>
          <VulnerabilitySelection
            selectedVulnerabilities={selectedVulnerabilities}
            onToggle={toggleVulnerability}
            selectAll={selectAll}
            onScanResults={handleScan}
            isScanning={isScanning}
            setIsScanning={setIsScanning}
          />
        </>
      ) : (
        <>
          <button
            onClick={handleBack}
            className="mb-4 px-4 py-2 bg-gray-700 text-white rounded hover:bg-gray-600 transition"
          >
            ⬅ Back to Scan
          </button>

          <VulnerabilityResults results={scanResults} />
        </>
      )}
    </div>
  );
}

export default VulnScanner;
