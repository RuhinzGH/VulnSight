
import React from "react";

function ResultsSummary({ results, url, onExport }) {
  const counts = {
    High: results.filter((r) => r.severity?.toLowerCase() === "high").length,
    Medium: results.filter((r) => r.severity?.toLowerCase() === "medium").length,
    Low: results.filter((r) => r.severity?.toLowerCase() === "low").length,
  };

  return (
    <div className="bg-gray-900 rounded-xl shadow-lg p-6 mb-8 border border-green-900 neon-border">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-4">
        <div>
          <h2 className="text-xl font-bold text-green-400">Scan Results</h2>
          <p className="text-gray-400">
            Target: <span className="text-green-400">{url}</span>
          </p>
        </div>

        <button
          className="mt-4 md:mt-0 flex items-center space-x-2 px-4 py-2 border border-green-700 rounded-lg bg-black hover:bg-gray-900 text-green-400"
          onClick={onExport}
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <span>Export Report</span>
        </button>
      </div>

      <div className="flex flex-wrap gap-4 mb-6">
        <div className="flex-1 min-w-[200px] bg-black p-4 rounded-lg border border-red-800">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-red-400 font-medium">High</p>
              <h3 className="text-3xl font-bold text-red-500">{counts.High}</h3>
            </div>
            <div className="p-2 bg-red-900/50 rounded-lg border border-red-800">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
          </div>
        </div>

        <div className="flex-1 min-w-[200px] bg-black p-4 rounded-lg border border-orange-800">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-orange-400 font-medium">Medium</p>
              <h3 className="text-3xl font-bold text-orange-500">{counts.Medium}</h3>
            </div>
            <div className="p-2 bg-orange-900/50 rounded-lg border border-orange-800">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-orange-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
        </div>

        <div className="flex-1 min-w-[200px] bg-black p-4 rounded-lg border border-green-800">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-green-400 font-medium">Low</p>
              <h3 className="text-3xl font-bold text-green-500">{counts.Low}</h3>
            </div>
            <div className="p-2 bg-green-900/50 rounded-lg border border-green-800">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ResultsSummary;
