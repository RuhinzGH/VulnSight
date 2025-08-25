import React, { useState, useEffect, useCallback } from "react";

function IntroAnimation({ onComplete }) {
  const [isVisible, setIsVisible] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => handleComplete(), 5000);
    return () => clearTimeout(timer);
  }, []);

  const handleComplete = useCallback(() => {
    setIsVisible(false);
    setTimeout(() => onComplete(), 500);
  }, [onComplete]);

  if (!isVisible) return null;

  const skullArt = `                      ______
                   .-"      "-.
                  /            \\
                 |              |
                 |,  .-.  .-.  ,|
                 | )(/  \\)( |
                 |/     /\\     \\|
       (@_       (_     ^^     _)
  _     ) \\\\|IIIIII|/_________________________
 ()@8@8{}<|-\\IIIIII/-|>
        )_/        \\          /
       (@           \--------\`;

  return (
    <div className="intro-overlay" onClick={handleComplete}>
      <pre className="ascii-skull">{skullArt}</pre>
      <div className="intro-text">VULNSIGHT INITIALIZING</div>
      <div className="intro-subtext">Advanced Vulnerability Scanner</div>
      <div className="click-anywhere">Click anywhere to continue</div>
    </div>
  );
}

export default IntroAnimation;
