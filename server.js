
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");
const { promisify } = require("util");

const scryptAsync = promisify(crypto.scrypt);
const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.disable("x-powered-by");
app.use(helmet());

const allowedOrigins = (process.env.FRONTEND_ORIGIN || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origin not allowed by CORS"));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json({ limit: "20kb" }));

// PostgreSQL connection
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 5,
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 30000,
    })
  : null;

if (pool) {
  pool.on("error", (error) => {
    console.error("Unexpected database pool error:", {
      code: error.code,
      message: error.message,
    });
  });
}

// Basic routes
app.get("/", (req, res) => {
  res.json({
    name: "FreeTube Backend API",
    status: "running",
    version: "1.1.0",
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "FreeTube Backend",
    databaseConfigured: Boolean(pool),
  });
});

app.get("/api/health/database", async (req, res, next) => {
  if (!pool) {
    return res.status(503).json({
      status: "not_configured",
      message: "Database has not been configured.",
    });
  }

  try {
    await pool.query("SELECT 1");
    return res.json({ status: "connected" });
  } catch (error) {
    return next(error);
  }
});

app.get("/api", (req, res) => {
  res.json({
    message: "Welcome to FreeTube API",
    endpoints: [
      "GET /api/health",
      "GET /api/health/database",
      "POST /api/auth/register",
      "POST /api/auth/login",
      "GET /api/auth/me",
    ],
  });
});

// Authentication configuration
function authReady(res) {
  if (!pool) {
    res.status(503).json({ error: "Database is not configured." });
    return false;
  }

  if (
    !process.env.JWT_SECRET ||
    Buffer.byteLength(process.env.JWT_SECRET, "utf8") < 32
  ) {
    res.status(503).json({
      error: "Authentication is not configured on the server.",
    });
    return false;
  }

  return true;
}

// Password hashing using Node.js scrypt
async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = await scryptAsync(password, salt, 64);

  return "scrypt$" + salt + "$" + derivedKey.toString("hex");
}

async function verifyPassword(password, storedHash) {
  try {
    const parts = String(storedHash).split("$");

    if (parts.length !== 3 || parts[0] !== "scrypt") {
      return false;
    }

    const salt = parts[1];
    const storedKey = Buffer.from(parts[2], "hex");

    if (storedKey.length !== 64) {
      return false;
    }

    const derivedKey = await scryptAsync(password, salt, 64);

    return crypto.timingSafeEqual(storedKey, derivedKey);
  } catch (_) {
    return false;
  }
}

// Signed access token. JWT_SECRET must remain private.
function createToken(user) {
  const now = Math.floor(Date.now() / 1000);

  const payload = {
    sub: user.id,
    username: user.username,
    role: user.role,
    iat: now,
    exp: now + 60 * 60 * 24 * 7,
  };

  const encodedPayload = Buffer.from(
    JSON.stringify(payload)
  ).toString("base64url");

  const signature = crypto
    .createHmac("sha256", process.env.JWT_SECRET)
    .update(encodedPayload)
    .digest("base64url");

  return encodedPayload + "." + signature;
}

function verifyToken(token) {
  if (typeof token !== "string" || token.length > 4096) {
    return null;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [encodedPayload, suppliedSignature] = parts;

  const expectedSignature = crypto
    .createHmac("sha256", process.env.JWT_SECRET)
    .update(encodedPayload)
    .digest();

  let actualSignature;

  try {
    actualSignature = Buffer.from(suppliedSignature, "base64url");
  } catch (_) {
    return null;
  }

  if (
    actualSignature.length !== expectedSignature.length ||
    !crypto.timingSafeEqual(actualSignature, expectedSignature)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf8")
    );

    if (
      !payload.sub ||
      !Number.isInteger(payload.exp) ||
      payload.exp <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return payload;
  } catch (_) {
    return null;
  }
}

// Verify Bearer token and confirm the account still exists.
async function requireAuth(req, res, next) {
  if (!authReady(res)) return;

  const authorization = req.get("authorization") || "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({ error: "Authentication required." });
  }

  const payload = verifyToken(match[1]);

  if (!payload) {
    return res.status(401).json({
      error: "Invalid or expired access token.",
    });
  }

  try {
    const result = await pool.query(
      `SELECT id, username, email, role, account_status, created_at
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [payload.sub]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Account not found." });
    }

    const user = result.rows[0];

    if (user.account_status !== "active") {
      return res.status(403).json({
        error: "This account is not active.",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

// Register
app.post("/api/auth/register", async (req, res, next) => {
  if (!authReady(res)) return;

  try {
    const username =
      typeof req.body.username === "string"
        ? req.body.username.trim()
        : "";

    const email =
      typeof req.body.email === "string"
        ? req.body.email.trim().toLowerCase()
        : "";

    const password =
      typeof req.body.password === "string"
        ? req.body.password
        : "";

    if (!/^[a-zA-Z0-9_]{3,50}$/.test(username)) {
      return res.status(400).json({
        error:
          "Username must be 3-50 characters using letters, numbers or underscores.",
      });
    }

    if (
      email.length > 255 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return res.status(400).json({
        error: "Enter a valid email address.",
      });
    }

    if (
      Buffer.byteLength(password, "utf8") < 8 ||
      Buffer.byteLength(password, "utf8") > 128
    ) {
      return res.status(400).json({
        error: "Password must be 8-128 bytes long.",
      });
    }

    const existing = await pool.query(
      `SELECT id
       FROM users
       WHERE LOWER(username) = LOWER($1)
          OR LOWER(email) = LOWER($2)
       LIMIT 1`,
      [username, email]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "Username or email is already registered.",
      });
    }

    const passwordHash = await hashPassword(password);

    const result = await pool.query(
      `INSERT INTO users
        (username, email, password_hash, role, account_status)
       VALUES ($1, $2, $3, 'creator', 'active')
       RETURNING id, username, email, role, account_status, created_at`,
      [username, email, passwordHash]
    );

    const user = result.rows[0];
    const token = createToken(user);

    return res.status(201).json({
      message: "Account created successfully.",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        account_status: user.account_status,
        created_at: user.created_at,
      },
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "Username or email is already registered.",
      });
    }

    next(error);
  }
});

// Login
app.post("/api/auth/login", async (req, res, next) => {
  if (!authReady(res)) return;

  try {
    const identifier =
      typeof req.body.identifier === "string"
        ? req.body.identifier.trim()
        : typeof req.body.email === "string"
        ? req.body.email.trim()
        : typeof req.body.username === "string"
        ? req.body.username.trim()
        : "";

    const password =
      typeof req.body.password === "string"
        ? req.body.password
        : "";

    if (!identifier || !password || identifier.length > 255) {
      return res.status(400).json({
        error: "Enter your email or username and password.",
      });
    }

    const result = await pool.query(
      `SELECT id, username, email, password_hash, role,
              account_status, created_at
       FROM users
       WHERE LOWER(email) = LOWER($1)
          OR LOWER(username) = LOWER($1)
       LIMIT 1`,
      [identifier]
    );

    const user = result.rows[0];

    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return res.status(401).json({
        error: "Invalid username/email or password.",
      });
    }

    if (user.account_status !== "active") {
      return res.status(403).json({
        error: "This account is not active.",
      });
    }

    const token = createToken(user);

    return res.json({
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        account_status: user.account_status,
        created_at: user.created_at,
      },
    });
  } catch (error) {
    next(error);
  }
});

// Current logged-in user
app.get("/api/auth/me", requireAuth, (req, res) => {
  const user = req.user;

  res.json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      account_status: user.account_status,
      created_at: user.created_at,
    },
  });
});

// Unknown routes
app.use((req, res) => {
  res.status(404).json({ error: "Route not found." });
});

// Central error handler
app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  if (error.message === "Origin not allowed by CORS") {
    return res.status(403).json({ error: "Origin not allowed." });
  }

  console.error("Request failed:", {
    code: error.code,
    message: error.message,
  });

  return res.status(500).json({
    error: "Internal server error.",
  });
});

// Start server
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`FreeTube API listening on port ${PORT}`);
});

// Graceful shutdown
async function shutdown() {
  server.close(async () => {
    if (pool) {
      await pool.end().catch(() => {});
    }

    process.exit(0);
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
