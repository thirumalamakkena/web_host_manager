# WebHostManager: A Comprehensive Client Data Management System

## Project Overview

WebHostManager is a sophisticated web application designed to streamline the management of client data for web hosting companies. The system provides a centralized platform for storing and managing essential client information, including website login credentials, expiry dates, domain management details, email access credentials, renewal charges, and more. By integrating powerful features such as user authentication, data encryption, and automated notifications, WebHostManager simplifies the process of managing client accounts while ensuring security and compliance.

## Technologies Used
[![My Skills](https://skillicons.dev/icons?i=js,react,nodejs,express,mysql)](https://skillicons.dev)
### Frontend

- **React**: A JavaScript library for building user interfaces.
- **React Bootstrap**: A library for integrating Bootstrap with React for responsive and visually appealing UI components.
- **CSS**: Styling for custom design elements and layout.

### Backend

- **Node.js**: A JavaScript runtime for building fast and scalable server-side applications.
- **Express.js**: A web application framework for Node.js, used for building the RESTful API.
- **bcrypt**: A library for hashing and salting passwords for secure storage.
- **cors**: A middleware for enabling Cross-Origin Resource Sharing in web applications.
- **mysql2**: A MySQL client for Node.js with support for Promises.

### Database
- MySQL (Hosted on Aiven): A relational database management system for storing and managing application data

### Other Tools

- **Postman**: An API client for testing and debugging API endpoints.
- **Git**: Version control system for tracking changes in the source code during development.

## Database Schema

The following schema represents the database structure used in the WebHostManager project:
 
![Untitled](https://github.com/yashasvi211/web-host-manager/assets/111164122/0b304f70-d4bb-458e-a8cd-fc03a289ae5f)

## Login Instructions
	
	To access the WebHostManager system, follow these steps:
	
	1. Navigate to the registration page.
	2. Create a dummy employee account by filling out the registration form.
	3. Use the registered credentials to log in to the system
## How to Create Your Own Backend
Setting Up the Project
``` javascript
import express, { json } from "express";
import mysql from "mysql2";
import cors from "cors";
import bcrypt from "bcrypt";

const app = express();
app.use(json());
app.use(cors());

const db = mysql.createConnection({
  // Your database connection details here
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to database:", err);
    return;
  }
  console.log("Connected to database");
});
```
## Register Route with Password Hashing

```javascript
app.post("/register", async (req, res) => {
  const { employee_name, username, password, position } = req.body;

  try {
    const [rows] = await db.promise().query("SELECT * FROM employees WHERE username = ?", [username]);

    if (rows.length > 0) {
      res.status(400).json({ error: "Username already exists" });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.promise().query(
      "INSERT INTO employees (employee_name, username, password, position) VALUES (?, ?, ?, ?)",
      [employee_name, username, hashedPassword, position]
    );

    res.status(201).json({
      message: "User registered successfully",
      userId: result.insertId,
    });
  } catch (err) {
    console.error("Error during register query:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});
```

## Login Route with Password Verification

```javascript
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  console.log(`Login attempt for username: ${username}`);

  try {
    const [rows] = await db.promise().query("SELECT * FROM employees WHERE username = ?", [username]);

    if (rows.length === 0) {
      console.log(`No employee found with username: ${username}`);
      res.status(401).json({ error: "Invalid username or password" });
      return;
    }

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      console.log(`Successful login for ${username}`);
      res.json({
        message: "Login successful",
        user: {
          id: user.id,
          employee_name: user.employee_name,
          username: user.username,
          position: user.position,
        },
      });
    } else {
      console.log(`Failed login attempt for ${username}: incorrect password`);
      res.status(401).json({ error: "Invalid username or password" });
    }
  } catch (err) {
    console.error("Error during login query:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});
```

## Fetch Users Route

```javascript
app.get("/users", async (req, res) => {
  try {
    const [results] = await db.promise().query(`
      SELECT u.*, up.expiry_date, p.plan_name
      FROM Users u
      LEFT JOIN UserPlans up ON u.user_id = up.user_id
      LEFT JOIN Plans p ON up.plan_id = p.plan_id
      ORDER BY u.user_id
    `);
    console.log("User data being sent:", JSON.stringify(results, null, 2));
    res.json(results);
  } catch (err) {
    console.error("Error during fetch users query:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});
```
## Fetch User Details Route

```javascript
app.get("/user/:id", async (req, res) => {
  const userId = req.params.id;

  try {
    const [results] = await db.promise().query(
      `
      SELECT u.*, up.expiry_date, p.plan_name, s.*, i.*, pm.*, st.*, su.*
      FROM Users u
      LEFT JOIN UserPlans up ON u.user_id = up.user_id
      LEFT JOIN Plans p ON up.plan_id = p.plan_id
      LEFT JOIN UserServers us ON u.user_id = us.user_id
      LEFT JOIN Servers s ON us.server_id = s.server_id
      LEFT JOIN Invoices i ON u.user_id = i.user_id
      LEFT JOIN PaymentMethods pm ON u.user_id = pm.user_id
      LEFT JOIN SupportTickets st ON u.user_id = st.user_id
      LEFT JOIN ServerUsage su ON us.user_server_id = su.user_server_id
      WHERE u.user_id = ?
    `,
      [userId]
    );

    if (results.length === 0) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    console.log("User detail data being sent:", JSON.stringify(results, null, 2));
    res.json(results);
  } catch (err) {
    console.error("Error during fetch user details query:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});
```

## Start the Server

```javascript
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```
