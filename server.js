
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const { Pool } = require("pg");

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
      // Allow requests without an Origin header, such as server health checks.
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Origin not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json({ limit: "100kb" }));

// PostgreSQL connection is enabled after DATABASE_URL is configured.
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_SSL === "false"
        ? false
        : { rejectUnauthorized: true },
      max: 5,
      connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 30000,
    })
  : null;

// Basic API information
app.get("/", (req, res) => {
  res.json({
    name: "FreeTube Backend API",
    status: "running",
    version: "1.0.0",
  });
});

// Health check for Render
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "FreeTube Backend",
    databaseConfigured: Boolean(pool),
  });
});

// Database connection test
app.get("/api/health/database", async (req, res, next) => {
  if (!pool) {
    return res.status(503).json({
      status: "not_configured",
      message: "Database has not been configured yet.",
    });
  }

  try {
    await pool.query("SELECT 1");
    return res.json({ status: "connected" });
  } catch (error) {
    return next(error);
  }
});

// Example API endpoint
app.get("/api", (req, res) => {
  res.json({
    message: "Welcome to FreeTube API",
    endpoints: [
      "GET /api/health",
      "GET /api/health/database",
    ],
  });
});

// Unknown routes
app.use((req, res) => {
  res.status(404).json({
    error: "Route not found",
  });
});

// Central error handler
app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  if (error.message === "Origin not allowed by CORS") {
    return res.status(403).json({
      error: "Origin not allowed",
    });
  }

  console.error("Request failed:", error.message);

  return res.status(500).json({
    error: "Internal server error",
  });
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`FreeTube API listening on port ${PORT}`);
});

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
