import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import "./UserDetails.css";

function UserDetail() {
  const { userId } = useParams();
  const [userData, setUserData] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    console.log("Fetching user details for userId:", userId);
    fetch(`http://localhost:3000/users/${userId}`)
      .then((response) => {
        console.log("Response status:", response.status);
        if (!response.ok) {
          return response.text().then((text) => {
            throw new Error(`Error ${response.status}: ${text}`);
          });
        }
        return response.json();
      })
      .then((data) => {
        console.log("Received user data:", data);
        setUserData(data);
        setIsLoading(false);
      })
      .catch((error) => {
        console.error("Error fetching user details:", error);
        setError(error.message);
        setIsLoading(false);
      });
  }, [userId]);

  if (isLoading) {
    return <div className="loading">Loading user details...</div>;
  }

  if (error) {
    return <div className="error">Error fetching user details: {error}</div>;
  }

  if (!userData || userData.length === 0) {
    return <div className="no-data">No user data available.</div>;
  }

  const user = userData; // Assuming the first result is the main user data

  return (
    <div className="user-detail">
      <h1>User Details for {user.username || "Unknown User"}</h1>

      <h2>Basic Information</h2>
      <table>
        <thead>
          <tr>
            <th>User ID</th>
            <th>Email</th>
            <th>First Name</th>
            <th>Last Name</th>
            <th>Phone Number</th>
            <th>Registration Date</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>{user.user_id}</td>
            <td>{user.email || "N/A"}</td>
            <td>{user.first_name || "N/A"}</td>
            <td>{user.last_name || "N/A"}</td>
            <td>{user.phone_number || "N/A"}</td>
            <td>{new Date(user.registration_date).toLocaleString()}</td>
          </tr>
        </tbody>
      </table>

      <h2>Plan Information</h2>
      <table>
        <thead>
          <tr>
            <th>Plan Name</th>
            <th>CPU Cores</th>
            <th>RAM</th>
            <th>Storage</th>
            <th>Bandwidth</th>
            <th>Monthly Price</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>{user.plan_name || "No Plan"}</td>
            <td>{user.cpu_cores || "N/A"}</td>
            <td>{user.ram_gb ? `${user.ram_gb} GB` : "N/A"}</td>
            <td>{user.storage_gb ? `${user.storage_gb} GB` : "N/A"}</td>
            <td>{user.bandwidth_gb ? `${user.bandwidth_gb} GB` : "N/A"}</td>
            <td>${user.price_monthly || "N/A"}</td>
          </tr>
        </tbody>
      </table>

      <h2>Server Information</h2>
      <table>
        <thead>
          <tr>
            <th>Server Name</th>
            <th>IP Address</th>
            <th>Location</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>{user.server_name || "N/A"}</td>
            <td>{user.ip_address || "N/A"}</td>
            <td>{user.location || "N/A"}</td>
            <td>{user.status || "N/A"}</td>
          </tr>
        </tbody>
      </table>

      <h2>Invoice Information</h2>
      <table>
        <thead>
          <tr>
            <th>Invoice ID</th>
            <th>Amount</th>
            <th>Issue Date</th>
            <th>Due Date</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>{user.invoice_id || "N/A"}</td>
            <td>${user.amount || "N/A"}</td>
            <td>
              {user.issue_date
                ? new Date(user.issue_date).toLocaleDateString()
                : "N/A"}
            </td>
            <td>
              {user.due_date
                ? new Date(user.due_date).toLocaleDateString()
                : "N/A"}
            </td>
            <td>{user.invoice_status || "N/A"}</td>
          </tr>
        </tbody>
      </table>

      <h2>Payment Method</h2>
      <table>
        <thead>
          <tr>
            <th>Method Type</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>{user.method_type || "N/A"}</td>
            <td>{user.payment_details || "N/A"}</td>
          </tr>
        </tbody>
      </table>

      <h2>Support Ticket</h2>
      <table>
        <thead>
          <tr>
            <th>Ticket ID</th>
            <th>Subject</th>
            <th>Description</th>
            <th>Status</th>
            <th>Created At</th>
            <th>Updated At</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>{user.ticket_id || "N/A"}</td>
            <td>{user.subject || "N/A"}</td>
            <td>{user.description || "N/A"}</td>
            <td>{user.ticket_status || "N/A"}</td>
            <td>
              {user.created_at
                ? new Date(user.created_at).toLocaleString()
                : "N/A"}
            </td>
            <td>
              {user.updated_at
                ? new Date(user.updated_at).toLocaleString()
                : "N/A"}
            </td>
          </tr>
        </tbody>
      </table>

      <h2>Server Usage</h2>
      <table>
        <thead>
          <tr>
            <th>CPU Usage</th>
            <th>RAM Usage</th>
            <th>Storage Usage</th>
            <th>Bandwidth Usage</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>
              {user.cpu_usage_percent ? `${user.cpu_usage_percent}%` : "N/A"}
            </td>
            <td>
              {user.ram_usage_percent ? `${user.ram_usage_percent}%` : "N/A"}
            </td>
            <td>
              {user.storage_usage_gb ? `${user.storage_usage_gb} GB` : "N/A"}
            </td>
            <td>
              {user.bandwidth_usage_gb
                ? `${user.bandwidth_usage_gb} GB`
                : "N/A"}
            </td>
            <td>
              {user.usage_timestamp
                ? new Date(user.usage_timestamp).toLocaleString()
                : "N/A"}
            </td>
          </tr>
        </tbody>
      </table>

      <Link to="/dashboard">
        <button className="back-button">Back to Dashboard</button>
      </Link>
    </div>
  );
}

export default UserDetail;
