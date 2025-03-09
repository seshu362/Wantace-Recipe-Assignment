const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
app.use(express.json()); // Middleware to parse JSON request bodies
app.use(cors());

// Create uploads directory if it doesn't exist
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Connect to SQLite database
const db = new sqlite3.Database("recipes.db", (err) => {
  if (err) console.error("Error connecting to database", err);
});

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    createdAt TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS recipes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    ingredients TEXT NOT NULL,
    instructions TEXT NOT NULL,
    imageUrl TEXT,
    categoryId INTEGER,
    userId INTEGER NOT NULL,
    createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id),
    FOREIGN KEY (categoryId) REFERENCES categories(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    userId INTEGER NOT NULL,
    createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id)
  )`);
});

// Helper function to generate JWT token
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, "your_jwt_secret_key", { expiresIn: "1h" });
};

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Access denied. No token provided." });

  jwt.verify(token, "your_jwt_secret_key", (err, decoded) => {
    if (err) {
      console.error("JWT verification error:", err); // Debugging
      return res.status(400).json({ error: "Invalid token." });
    }
    req.userId = decoded.id;
    next();
  });
};

// Middleware to log API requests and request body
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  console.log("Request Body:", req.body); // Log the request body for debugging
  next();
});

// Configure Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

// Serve uploaded images statically
app.use("/uploads", express.static("uploads"));

// Add image upload endpoint
app.post("/upload", upload.single("image"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  res.json({ imageUrl: `http://localhost:5000/uploads/${req.file.filename}` });
});

// User Signup
app.post(
    "/signup",
    [
      body("name").notEmpty().withMessage("Name is required"),
      body("email").isEmail().withMessage("Invalid email"),
      body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
    ],
    async (req, res) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  
      const { name, email, password } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
  
      db.run(
        `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`,
        [name, email, hashedPassword],
        function (err) {
          if (err) {
            if (err.message.includes("UNIQUE constraint failed")) {
              return res.status(400).json({ error: "Email already exists" });
            }
            console.error("Database error:", err); // Debugging
            return res.status(500).json({ error: "Failed to create user" });
          }
  
          // Generate JWT token after successful signup
          const token = jwt.sign({ id: this.lastID }, "your_jwt_secret_key", { expiresIn: "1h" });
  
          // Return the token along with user data
          res.status(201).json({ id: this.lastID, name, email, token });
        }
      );
    }
  );

// User Login
app.post(
  "/login",
  [
    body("email").isEmail().withMessage("Invalid email"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;

    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
      if (err) {
        console.error("Database error:", err); // Debugging
        return res.status(500).json({ error: "Failed to fetch user" });
      }
      if (!user) return res.status(404).json({ error: "User not found" });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

      const token = generateToken(user.id);
      res.json({ token });
    });
  }
);

// GET /recipes: Retrieves all recipes for the authenticated user
app.get("/recipes", authenticateToken, (req, res) => {
  console.log("User ID:", req.userId); // Debugging: Check if the user ID is extracted correctly

  db.all(`SELECT * FROM recipes WHERE userId = ?`, [req.userId], (err, recipes) => {
    if (err) {
      console.error("Database error:", err); // Debugging: Check for database errors
      return res.status(500).json({ error: "Failed to fetch recipes" });
    }
    console.log("Recipes fetched:", recipes); // Debugging: Check the fetched recipes
    res.status(200).json(recipes || []);
  });
});

// GET /recipes/:id: Fetch a single recipe by ID
app.get("/recipes/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  const userId = req.userId;

  db.get(
    `SELECT * FROM recipes WHERE id = ? AND userId = ?`,
    [id, userId],
    (err, recipe) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Failed to fetch recipe" });
      }
      if (!recipe) {
        return res.status(404).json({ error: "Recipe not found" });
      }
      res.status(200).json(recipe);
    }
  );
});

// POST /recipes: Creates a new recipe
app.post(
  "/recipes",
  authenticateToken,
  [
    body("title").notEmpty().withMessage("Title is required"),
    body("description").notEmpty().withMessage("Description is required"),
    body("ingredients").notEmpty().withMessage("Ingredients are required"),
    body("instructions").notEmpty().withMessage("Instructions are required"),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { title, description, ingredients, instructions, categoryId, imageUrl } = req.body;

    db.run(
      `INSERT INTO recipes (title, description, ingredients, instructions, imageUrl, categoryId, userId) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [title, description, ingredients, instructions, imageUrl, categoryId, req.userId],
      function (err) {
        if (err) {
          console.error("Database error:", err); // Debugging
          return res.status(500).json({ error: "Failed to add recipe" });
        }
        res.status(201).json({
          id: this.lastID,
          title,
          description,
          ingredients,
          instructions,
          imageUrl,
          categoryId,
        });
      }
    );
  }
);

// PUT /recipes/:id: Updates an existing recipe
app.put("/recipes/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  const { title, description, ingredients, instructions, categoryId, imageUrl } = req.body;

  console.log("Request Body:", req.body); // Debugging: Log the request body
  console.log("User ID:", req.userId); // Debugging: Log the user ID

  db.run(
    `UPDATE recipes SET title = ?, description = ?, ingredients = ?, instructions = ?, categoryId = ?, imageUrl = ? WHERE id = ? AND userId = ?`,
    [title, description, ingredients, instructions, categoryId, imageUrl, id, req.userId],
    function (err) {
      if (err) {
        console.error("Database error:", err); // Debugging
        return res.status(500).json({ error: "Failed to update recipe" });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: "Recipe not found or unauthorized" });
      }
      res.status(200).json({ message: "Recipe updated successfully" });
    }
  );
});



// Default route for invalid API requests
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// Start server
app.listen(5000, () => console.log("Server running on port 5000"));