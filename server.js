const express = require("express");
const app = express();
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const { error } = require("console");

app.use(cors());
app.use(express.json());

const dbPath = path.join(__dirname, "todos.db");

let db;

const initDb = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    await db.run(
      `CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(255) PRIMARY KEY ,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
            )`
    );

    await db.run(
      `CREATE TABLE IF NOT EXISTS todos(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            todo TEXT NOT NULL,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
            )`
    );

    app.listen(10000, () => {
      console.log("Server running on port 10000");
    });
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
};

initDb();

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token is required" });

  jwt.verify(token, "JWT_SECRET", (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};

app.post("/signup", async (req, res) => {
  const { id, name, email, password } = req.body;
  try {
    const existingUser = await db.get(`SELECT * FROM users WHERE email = ?`, [
      email,
    ]);
    if (existingUser)
      return res.status(400).json({ error: "user already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.run(
      `INSERT INTO users (id,name,email,password)
        VALUES (?,?,?,?)        
        `,
      [id, name, email, hashedPassword]
    );
    res.status(200).json({ message: "User created successfully" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to create user" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ error: "Invalid password" });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, "JWT_SECRET", {
    expiresIn: "30d",
  });
  res.status(200).json({ token });
});

app.post("/newtodo", authenticateToken, async (req, res) => {
  const { todo } = req.body;
  const { id: userId } = req.user;

  if (!todo) {
    return res.status(400).json({ error: "Todo content is required" });
  }

  try {
    const result = await db.run(
      `INSERT INTO todos (todo, user_id) VALUES (?, ?)`,
      [todo, userId]
    );

    const newTodo = await db.get(`SELECT * FROM todos WHERE id = ?`, [
      result.lastID,
    ]);

    res.status(200).json(newTodo);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to add todo" });
  }
});

app.get("/gettodos", authenticateToken, async (req, res) => {
  const { id: userId } = req.user;
  try {
    const todos = await db.all(`SELECT * FROM todos WHERE user_id =?`, [
      userId,
    ]);
    res.status(200).json(todos);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to get todos" });
  }
});

app.delete("/deletetodo", async (req, res) => {
  const { id } = req.body;
  if (!id) {
    res.status(404).json({ error: "Id is required" });
  }
  try {
    await db.run(`DELETE FROM todos WHERE id =?`, [id]);
    res.status(200).json({ message: "Todo deleted successfully" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to delete todo" });
  }
});

app.put("/updatetodo", async (req, res) => {
  const { id, todo } = req.body;
  if (!id || !todo) {
    res.status(400).json({ error: "Id and todo content are required" });
  }
  try {
    await db.run(`UPDATE todos SET todo =? WHERE id =?`, [todo, id]);
    const updatedTodo = await db.get(`SELECT * FROM todos WHERE id =?`, [id]);
    res.status(200).json(updatedTodo);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Failed to update todo" });
  }
});
