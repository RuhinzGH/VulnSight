import React, { useEffect, useRef } from "react";

function MatrixBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    // Retina & responsive handling
    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      canvas.width = window.innerWidth * dpr;
      canvas.height = window.innerHeight * dpr;
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.scale(dpr, dpr);
    };
    resize();

    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$#@%&*()!?><[]{}";
    const fontSize = 16; // slightly larger and clearer
    let columns = Math.floor(window.innerWidth / fontSize);
    let drops = new Array(columns).fill(1);

    const draw = () => {
      // Slightly higher alpha = slower fade (better trails)
      ctx.fillStyle = "rgba(0, 0, 0, 0.1)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.font = `${fontSize}px monospace`;

      for (let i = 0; i < drops.length; i++) {
        const text = characters[Math.floor(Math.random() * characters.length)];

        // Draw trailing character (green)
        ctx.fillStyle = "rgba(0, 255, 65, 0.75)";
        ctx.shadowColor = "#00ff41";
        ctx.shadowBlur = 6;
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        // Draw leading character (white head for visibility)
        ctx.fillStyle = "rgba(255, 255, 255, 0.9)";
        ctx.shadowColor = "#ffffff";
        ctx.shadowBlur = 12;
        ctx.fillText(text, i * fontSize, drops[i] * fontSize - fontSize);

        // Reset drop randomly when it reaches bottom
        if (drops[i] * fontSize > window.innerHeight && Math.random() > 0.975) {
          drops[i] = 0;
        }

        drops[i]++;
      }
    };

    const interval = setInterval(draw, 40);

    const onResize = () => {
      resize();
      columns = Math.floor(window.innerWidth / fontSize);
      drops = new Array(columns).fill(1);
    };
    window.addEventListener("resize", onResize);

    return () => {
      clearInterval(interval);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="matrix-background fixed top-0 left-0 w-full h-full z-0"
    />
  );
}

export default MatrixBackground;
