import React, { useEffect, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import "./Dashboad.css";

function Dashboard({ user }) {
  const navigate = useNavigate();
  const [users, setUsers] = useState([]);
  const [filteredUsers, setFilteredUsers] = useState([]);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetch("http://localhost:3000/users")
      .then((response) => {
        if (!response.ok) {
          return response.text().then((text) => {
            throw new Error(`Error ${response.status}: ${text}`);
          });
        }
        return response.json();
      })
      .then((data) => {
        console.log("Fetched user data:", data);
        setUsers(data);
        setFilteredUsers(data);
        setIsLoading(false);
      })
      .catch((error) => {
        console.error("Error fetching users:", error);
        setError(error.message);
        setIsLoading(false);
      });
  }, []);

  useEffect(() => {
    const results = users.filter((user) =>
      Object.values(user).some(
        (value) =>
          value &&
          value.toString().toLowerCase().includes(searchTerm.toLowerCase())
      )
    );
    setFilteredUsers(results);
  }, [searchTerm, users]);

  const handleLogout = () => {
    localStorage.removeItem("user");
    navigate("/login");
  };

  const goToProfile = () => {
    navigate("/profile");
  };

  const handleSearch = (event) => {
    setSearchTerm(event.target.value);
  };

  if (isLoading) {
    return <div>Loading users...</div>;
  }

  if (error) {
    return <div>Error fetching users: {error}</div>;
  }

  return (
    <div className="dashboard">
      <h1>Welcome to the Dashboard, {user.employee_name}!</h1>

      <div className="actions">
        <button onClick={goToProfile}>Go to Profile</button>
      </div>

      <h2>Users</h2>
      <input
        type="text"
        placeholder="Search users..."
        value={searchTerm}
        onChange={handleSearch}
        className="search-bar"
      />
      <table>
        <thead>
          <tr>
            <th>User ID</th>
            <th>Username</th>
            <th>Email</th>
            <th>First Name</th>
            <th>Last Name</th>
            <th>Phone Number</th>
            <th>Registration Date</th>
            <th>Plan Name</th>
            <th>Renewal Ending Date</th>
          </tr>
        </thead>
        <tbody>
          {filteredUsers.map((user) => (
            <tr key={user.user_id}>
              <td>{user.user_id}</td>
              <td>
                <Link to={`/user/${user.user_id}`}>{user.username}</Link>
              </td>
              <td>{user.email}</td>
              <td>{user.first_name}</td>
              <td>{user.last_name}</td>
              <td>{user.phone_number}</td>
              <td>
                {user.registration_date
                  ? new Date(user.registration_date).toLocaleDateString()
                  : "N/A"}
              </td>
              <td>{user.plan_name || "No Plan"}</td>
              <td>
                {user.expiry_date
                  ? new Date(user.expiry_date).toLocaleDateString()
                  : "N/A"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default Dashboard;
