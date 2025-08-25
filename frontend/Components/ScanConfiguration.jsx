
import React from "react";

function ScanConfiguration({
  url,
  onUrlChange,
  onScan,
  isScanning,
  scanProgress,
  selectedCount,
}) {
  return (
    <div className="bg-gray-900 rounded-xl shadow-lg p-6 mb-8 border border-green-900 neon-border">
      <h2 className="text-xl font-bold text-green-400 mb-4">Target Configuration</h2>

      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-300 mb-2">
          Target URL
        </label>
        <div className="flex">
          <input
            type="text"
            className="flex-grow px-4 py-2 rounded-l-lg border border-green-700 bg-black focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500 text-green-400"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => onUrlChange(e.target.value)}
            disabled={isScanning}
          />
          <button
            className="px-4 py-2 bg-green-900 border border-green-500 text-green-400 rounded-r-lg hover:bg-green-800 neon-border flex items-center"
            onClick={onScan}
            disabled={isScanning}
          >
            {isScanning ? (
              <>
                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-green-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Scanning...
              </>
            ) : (
              <>
                <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                Start Scan
              </>
            )}
          </button>
        </div>
      </div>

      {isScanning && (
        <div className="mb-6">
          <div className="flex justify-between text-sm text-gray-400 mb-1">
            <span>Scanning in progress...</span>
            <span>{Math.min(scanProgress, 100)}%</span>
          </div>
          <div className="h-2 w-full bg-gray-800 rounded-full overflow-hidden">
            <div
              className="h-full progress-bar rounded-full"
              style={{ width: ${Math.min(scanProgress, 100)}% }}
            ></div>
          </div>
          <div className="mt-2 text-xs text-gray-500">
            {selectedCount} vulnerability checks selected
          </div>
        </div>
      )}
    </div>
  );
}

export default ScanConfiguration;
