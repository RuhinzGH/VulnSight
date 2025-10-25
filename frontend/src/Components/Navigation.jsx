import "./Navigation.css";
import React, { useContext, useState, useRef, useEffect } from "react";
import { LockClosedIcon } from "@heroicons/react/24/solid";
import { useNavigate } from "react-router-dom";
import { UserContext } from "../UserContext.jsx";
import logo from "./assets/logo.png"; // 


function Navigation({ currentTime, currentDate }) {
  const navigate = useNavigate();
  const { user, logout } = useContext(UserContext);

  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);

  const handleCircleClick = () => {
    if (user) {
      setDropdownOpen((prev) => !prev);
    } else {
      navigate("/login");
    }
  };

  // Close dropdown if click outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleLogout = () => {
    logout();
    setDropdownOpen(false);
  };

  return (
    <nav className="main-nav-container">
      <div className="nav-content-wrapper">
        {/* Left side: Logo + Title */}
        <div className="nav-left-group">
          <div className="logo-icon">
  <img src={logo} alt="Vulnsight Logo" className="logo-img" />
</div>

        </div>

        {/* Right side: Time + Date + VS Circle */}
        <div className="nav-right-group" ref={dropdownRef}>
  <div className="nav-datetime-user">
    <span className="datetime-text">
      {currentTime} // {currentDate}
    </span>

    {user && (
      <p className="nav-user-info">
        Logged in as: <strong>{user.email}</strong>
      </p>
    )}
  </div>

{/* Wrap VS circle and dropdown in a relative container */}
  <div className="vs-wrapper" style={{ position: "relative" }}>
    <div className="vs-circle" onClick={handleCircleClick}>
      <span className="neon-text vs-text">VS</span>
    </div>

{/* Dropdown for logged-in user */}
    {user && dropdownOpen && (
      <div className="vs-dropdown">
        <button className="logout-btn" onClick={handleLogout}>
          Logout
        </button>
      </div>
    )}
  </div>
</div>



      </div>
    </nav>
  );
}

export default Navigation;
