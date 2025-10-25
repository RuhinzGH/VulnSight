
import React from "react";

function Navigation({ currentTime, currentDate }) {
  return (
    <nav className="bg-black border-b border-green-500 p-4">
      <div className="container mx-auto flex justify-between items-center">
        <div className="flex items-center space-x-3">
          <div className="h-10 w-10 rounded-lg bg-black border-2 border-green-500 flex items-center justify-center pulse">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h1 className="text-xl font-bold text-green-400 neon-text">
            VULN<span className="text-white">SIGHT</span>
          </h1>
        </div>

        <div className="flex items-center space-x-4">
          <div className="text-xs text-green-400 hidden md:block">
            <span>{currentTime}</span> | <span>{currentDate}</span>
          </div>
          <div className="h-8 w-8 rounded-full bg-green-900 border border-green-500 flex items-center justify-center text-green-400 font-medium">
            VS
          </div>
        </div>
      </div>
    </nav>
  );
}

export default Navigation;
