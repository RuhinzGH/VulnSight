import React, { useState, useEffect, useContext } from "react";
import { useNavigate } from "react-router-dom";
import Navigation from "./Navigation";
import { UserContext } from "../UserContext.jsx"; // make sure path is correct
import "./Login.css";

function Login() {
  const navigate = useNavigate();
  const { login } = useContext(UserContext); // context login function

  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Time/Date for Navigation
  const [currentTime, setCurrentTime] = useState("");
  const [currentDate, setCurrentDate] = useState("");

  // ---------------- Clock ----------------
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const timeStr = now.toLocaleTimeString("en-US", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      });
      const dateStr = now.toLocaleDateString("en-US", {
        month: "2-digit",
        day: "2-digit",
        year: "numeric",
      });
      setCurrentTime(timeStr);
      setCurrentDate(dateStr);
    };

    updateTime();
    const timerId = setInterval(updateTime, 1000);
    return () => clearInterval(timerId);
  }, []);

  // ---------------- Tab Switch ----------------
  const handleTabSwitch = (tab) => {
    setIsLogin(tab === "login");
    setEmail("");
    setPassword("");
    setName("");
    setError("");
  };

  // ---------------- Form Submit ----------------
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    const endpoint = isLogin ? "/login" : "/signup";

    try {
      const res = await fetch(`http://localhost:8000${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email, password, name: isLogin ? undefined : name }),
      });

      const data = res.ok ? await res.json() : { status: "error", message: `HTTP ${res.status}` };


      if (data.status === "success") {
        login({ email }); // ✅ FIX: pass an object instead of string
        navigate("/dashboard"); // navigate to dashboard
      } else {
        setError(data.message || "Authentication failed");
      }
    } catch (err) {
      setError("Server error: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  // ---------------- Render ----------------
  return (
  <div className="login-container">
    {/* Sticky Navigation */}
    <Navigation currentTime={currentTime} currentDate={currentDate} />

    {/* Scrollable content below the fixed navbar */}
    <div className="login-content">
      <div className="card-wrapper">
        <div className="login-card">
          {/* Close Button */}
          <span className="close-btn" onClick={() => navigate("/")}>
            &times;
          </span>

          <h2 className="login-title">{isLogin ? "Login" : "Sign Up"}</h2>

          {/* Tab Switcher */}
          <div className="tab-switcher">
            <button
              className={`tab-btn ${isLogin ? "active" : ""}`}
              onClick={() => handleTabSwitch("login")}
            >
              Login
            </button>
            <button
              className={`tab-btn ${!isLogin ? "active" : ""}`}
              onClick={() => handleTabSwitch("signup")}
            >
              Sign Up
            </button>
          </div>

          {error && <p className="error-message">{error}</p>}

          {/* Form */}
          <form onSubmit={handleSubmit} autoComplete="off">
            {!isLogin && (
              <div className="form-group">
                <div className="icon-input-wrapper">
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Full Name"
                    required
                  />
                </div>
              </div>
            )}

            <div className="form-group">
              <div className="icon-input-wrapper">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Email"
                  required
                  autoFocus
                />
              </div>
            </div>

            <div className="form-group">
              <div className="icon-input-wrapper">
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Password"
                  required
                />
              </div>
            </div>

            <button type="submit" className="login-btn" disabled={loading}>
              {loading ? "Please wait..." : isLogin ? "Login" : "Sign Up"}
            </button>
            <p className="hint">Press Enter ↵ to continue</p>
          </form>

          {/* Footer */}
          <div className="card-footer">
            {isLogin ? (
              <p>
                Don't have an account?{" "}
                <span
                  className="link-text"
                  onClick={() => handleTabSwitch("signup")}
                >
                  Sign Up now
                </span>
              </p>
            ) : (
              <p>
                Already have an account?{" "}
                <span
                  className="link-text"
                  onClick={() => handleTabSwitch("login")}
                >
                  Login here
                </span>
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  </div>
);
}

export default Login;
