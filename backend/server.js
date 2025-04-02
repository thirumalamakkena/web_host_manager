import express, { json } from "express";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(json());
app.use(cors());



// ========================
// SQLite Database Connection
// ========================
const db = await open({
  filename: './web_manager.db',  // SQLite database file
  driver: sqlite3.Database,
});

// ========================
// Middleware: Authenticate JWT
// ========================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  console.log("Auth Header:", authHeader);
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Access denied" });

  jwt.verify(token, "hbjhj", (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });

    req.user = user;
    next();
  });
};

// ========================
// Register Route with Password Hashing
// ========================
app.post("/register", async (req, res) => {
  const { employee_name, username, password, position } = req.body;
  try {

    // Check if username exists
    const existingUser = await db.get(
      "SELECT * FROM employees WHERE username = ?",
      [username]
    );

    if (existingUser) {
      return res.status(400).json({ error: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user
    await db.run(
      `INSERT INTO employees (employee_name, username, password, position) 
       VALUES (?, ?, ?, ?)`,
      [employee_name, username, hashedPassword, position]
    );

    res.status(201).json({ message: "User registered successfully" });

  } catch (err) {
    console.error("Error during register:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========================
// Login Route with JWT
// ========================
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {

    const user = await db.get(
      "SELECT * FROM employees WHERE username = ?",
      [username]
    );

    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      "hbjhj",
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        employee_name: user.employee_name,
        username: user.username,
        position: user.position,
      },
    });

  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========================
// Fetch All Users with Pagination
// ========================
app.get("/users", async (req, res) => {
  const { page = 1, limit = 10 } = req.query;
  const offset = (page - 1) * limit;

  try {

    const users = await db.all(
      `SELECT u.*, up.expiry_date, p.plan_name
       FROM Users u
       LEFT JOIN user_plans up ON u.user_id = up.user_id
       LEFT JOIN Plans p ON up.plan_id = p.plan_id
       ORDER BY u.user_id
       LIMIT ? OFFSET ?`,
      [Number(limit), Number(offset)]
    );

    res.json(users);

  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========================
// Fetch Individual User Details
// ========================

app.get("/users/:userId", async (req, res) => {
  const { userId } = req.params;

  try {

    const user = await db.get(
      `SELECT 
         u.*,
         up.user_plan_id, up.start_date, up.expiry_date, up.auto_renew,
         p.plan_name, p.cpu_cores, p.ram_gb, p.storage_gb, p.bandwidth_gb, p.price_monthly,
         s.server_id, s.server_name, s.ip_address, s.location, s.status,
         i.invoice_id, i.amount, i.issue_date, i.due_date, i.status AS invoice_status,
         pm.payment_method_id, pm.method_type, pm.details AS payment_details,
         st.ticket_id, st.subject, st.description, st.status AS ticket_status, st.created_at, st.updated_at,
         su.usage_id, su.cpu_usage_percent, su.ram_usage_percent, su.storage_usage_gb, su.bandwidth_usage_gb, su.timestamp AS usage_timestamp
       FROM Users u
       LEFT JOIN user_plans up ON u.user_id = up.user_id
       LEFT JOIN Plans p ON up.plan_id = p.plan_id
       LEFT JOIN user_servers us ON u.user_id = us.user_id
       LEFT JOIN Servers s ON us.server_id = s.server_id
       LEFT JOIN Invoices i ON u.user_id = i.user_id
       LEFT JOIN payment_methods pm ON u.user_id = pm.user_id
       LEFT JOIN support_tickets st ON u.user_id = st.user_id
       LEFT JOIN server_usage su ON us.user_server_id = su.user_server_id
       WHERE u.user_id = ?`,
      [userId]
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);

  } catch (err) {
    console.error("Error fetching user details:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========================
// Error Handling Middleware
// ========================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal server error" });
});

// ========================
// Start the Server
// ========================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  //connect database 


  console.log(`Server running on port ${PORT}`);
});
