import React, { useState, useEffect, useCallback } from "react";
import "./IntroAnimation.css";
import SkullVideo from "./assets/skull-intro.mp4";
import Logo from "./assets/logo.png"; 

function IntroAnimation({ onComplete }) {
  const [isVisible, setIsVisible] = useState(true);

  const handleComplete = useCallback(() => {
    setIsVisible(false);
    setTimeout(() => {
      if (onComplete) onComplete();
    }, 500); // slight fade-out
  }, [onComplete]);

  // Auto-complete after 15s
  useEffect(() => {
    const timer = setTimeout(() => handleComplete(), 15000);
    return () => clearTimeout(timer);
  }, [handleComplete]);

  if (!isVisible) return null;

  return (
    <div className="intro-wrapper" onClick={handleComplete}>
      {/* Background video */}
      <video
        className="intro-video"
        src={SkullVideo}
        autoPlay
        muted
        playsInline
        loop
      />

      {/* Overlay content */}
      <div className="intro-overlay">
        {/* Logo at top-left */}
        <img src={Logo} alt="VulnSight Logo" className="intro-logo" />

        {/* Text beside skull */}
        <div className="intro-text">
          <h1 className="intro-title">VulnSight Initializing</h1>
          <p className="intro-subtitle">Advanced Vulnerability Scanner</p>
          <button className="intro-button">Click anywhere to continue</button>
        </div>
      </div>
    </div>
  );
}

export default IntroAnimation;
