import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Profile.css";

function Profile({ user }) {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true); // State to manage loading state
  const [error, setError] = useState(null); // State to handle fetch errors

  useEffect(() => {
    setLoading(true); // Set loading state when component mounts

    // Simulating async operation (fetching user data)
    // Replace with actual async operation to fetch user data if needed
    setTimeout(() => {
      setLoading(false); // Set loading to false after simulation
    }, 1000); // Adjust time as needed or remove this if not using async fetch

    return () => {
      // Clean-up function (optional)
    };
  }, []); // Empty dependency array to run effect only once

  const handleBackToDashboard = () => {
    navigate("/dashboard");
  };

  const handleLogout = () => {
    // Clear user data from local storage and navigate to login page
    localStorage.removeItem("user");
    navigate("/login");
  };

  if (loading) {
    return <div>Loading...</div>; // Render a loading indicator while fetching data
  }

  if (error) {
    return <div>Error: {error.message}</div>; // Render an error message if fetch fails
  }

  return (
    <div className="profile-container">
      <h1>Employee Profile</h1>
      <p>Name: {user.employee_name}</p>
      <p>Username: {user.username}</p>
      <p>Position: {user.position}</p>
      <button onClick={handleLogout}>Logout</button> {/* Logout button */}
      <button onClick={handleBackToDashboard}>Back to Dashboard</button>
    </div>
  );
}

export default Profile;
