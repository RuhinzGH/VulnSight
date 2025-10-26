import { createContext, useState, useEffect } from "react";
import axios from "axios";

export const UserContext = createContext();

export const UserProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    // Try to load user from localStorage (temporary session)
    const savedUser = localStorage.getItem("user");
    return savedUser ? JSON.parse(savedUser) : null;
  });

  const [userScans, setUserScans] = useState(() => {
    const savedScans = localStorage.getItem("userScans");
    return savedScans ? JSON.parse(savedScans) : [];
  });

  const [loading, setLoading] = useState(true);

  // ---------------- Fetch current user on mount ----------------
  useEffect(() => {
  const SESSION_DURATION = 60 * 60 * 1000; // 1 hour
  const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

  const fetchUser = async () => {
    // 🕒 Check session expiry
    const loginTime = localStorage.getItem("loginTime");
    if (loginTime && Date.now() - loginTime > SESSION_DURATION) {
      console.warn("Session expired due to 1-hour limit.");
      logout();
      setLoading(false);
      return;
    }

    try {
      const res = await axios.get(`${BASE_URL}/current-user`, {
        withCredentials: true,
      });

      if (res.data.email) {
        const userData = {
          email: res.data.email,
          id: res.data.id,
          name: res.data.name,
        };
        setUser(userData);
        localStorage.setItem("user", JSON.stringify(userData));

        // Fetch user scans
        const scansRes = await axios.get(`${BASE_URL}/user-scans`, {
          withCredentials: true,
        });

        if (scansRes.data.status === "success") {
          setUserScans(scansRes.data.scans);
          localStorage.setItem("userScans", JSON.stringify(scansRes.data.scans));
        }
      } else {
        setUser(null);
        setUserScans([]);
        localStorage.clear();
      }
    } catch (err) {
      if (err.response?.status === 401) {
        console.warn("Session expired. Logging out...");
        logout();
      } else {
        console.error("Failed to fetch current user:", err);
      }
      setUser(null);
      setUserScans([]);
      localStorage.clear();
    } finally {
      setLoading(false);
    }
  };

  fetchUser();

  // 🚫 Remove full-session clearing on reload (keeps user logged in)
  // Instead, session expires naturally after 1 hour
}, []);


// ---------------- Login ----------------
const login = async (userObj) => {
  setUser(userObj);
  localStorage.setItem("user", JSON.stringify(userObj));
  localStorage.setItem("loginTime", Date.now()); // 🕒 store login time

  const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

  try {
    const res = await axios.get(`${BASE_URL}/user-scans`, {
      withCredentials: true,
    });

    if (res.data.status === "success") {
      setUserScans(res.data.scans);
      localStorage.setItem("userScans", JSON.stringify(res.data.scans));
    }
  } catch (err) {
    if (err.response?.status === 401) {
      console.warn("Session expired. Logging out...");
      logout();
    } else {
      console.error("Failed to fetch current user:", err);
    }
    setUser(null);
    setUserScans([]);
    localStorage.clear();
  }
};

  // ---------------- Logout ----------------
  const logout = async () => {
    try {
      await axios.post(
        "http://localhost:8000/logout",
        {},
        { withCredentials: true }
      );
    } catch (err) {
      console.error("Logout error:", err);
    } finally {
      setUser(null);
      setUserScans([]);
      localStorage.clear(); // remove all user data
    }
  };

  // ---------------- Add a new scan ----------------
  const addScan = (scan) => {
    const updatedScans = [scan, ...userScans];
    setUserScans(updatedScans);
    localStorage.setItem("userScans", JSON.stringify(updatedScans));
  };

  return (
    <UserContext.Provider
      value={{ user, userScans, login, logout, addScan, loading }}
    >
      {children}
    </UserContext.Provider>
  );
};
