import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Login from "./credential/Login";
import Register from "./credential/Register";
import Dashboard from "./home/Dashboad";
import Profile from "./home/Profile";
import UserDetail from "./home/UserDetails";
function App() {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const storedUser = localStorage.getItem("user");
    if (storedUser) {
      setUser(JSON.parse(storedUser));
    }
  }, []);

  return (
    <Router>
      <Routes>
        <Route path="/" element={<Login setUser={setUser} />} />
        <Route path="/login" element={<Login setUser={setUser} />} />
        <Route path="/register" element={<Register />} />
        <Route
          path="/dashboard"
          element={
            user ? (
              <Dashboard user={user} setUser={setUser} />
            ) : (
              <Login setUser={setUser} />
            )
          }
        />
        <Route path="/user/:userId" element={<UserDetail />} />
        <Route path="/profile" element={<Profile user={user} />} />
      </Routes>
    </Router>
  );
}

export default App;
