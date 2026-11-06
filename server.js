require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");
const { promisify } = require("util");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const scryptAsync = promisify(crypto.scrypt);

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "100kb" }));

const allowedOrigins = (process.env.FRONTEND_ORIGIN || "")
  .split(",").map(x => x.trim()).filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || !allowedOrigins.length || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 5,
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 30000,
      ssl: process.env.DATABASE_SSL === "false"
        ? false
        : { rejectUnauthorized: false }
    })
  : null;

if (pool) {
  pool.on("error", e => console.error("Database pool error:", e.message));
}

const cloudinaryConfigured = Boolean(
  process.env.CLOUDINARY_CLOUD_NAME &&
  process.env.CLOUDINARY_API_KEY &&
  process.env.CLOUDINARY_API_SECRET
);

if (cloudinaryConfigured) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
  });
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024, files: 1 },
  fileFilter(req, file, callback) {
    const types = [
      "image/jpeg", "image/png", "image/webp", "image/gif",
      "video/mp4", "video/webm", "video/quicktime"
    ];
    if (!types.includes(file.mimetype)) {
      return callback(new Error(
        "Unsupported file type. Use JPG, PNG, WEBP, GIF, MP4 or WEBM."
      ));
    }
    callback(null, true);
  }
});

function cleanText(value, max = 2000) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

function authReady(res) {
  if (!pool) {
    res.status(503).json({ error: "DATABASE_URL is not configured." });
    return false;
  }
  if (!process.env.JWT_SECRET ||
      Buffer.byteLength(process.env.JWT_SECRET, "utf8") < 32) {
    res.status(503).json({
      error: "JWT_SECRET must contain at least 32 bytes."
    });
    return false;
  }
  return true;
}

function makeUsernameBase(name) {
  let username = String(name || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 40);
  return username.length < 3 ? "user" : username;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  return scryptAsync(password, salt, 64)
    .then(key => `scrypt$${salt}$${key.toString("hex")}`);
}

async function verifyPassword(password, storedHash) {
  try {
    const parts = String(storedHash).split("$");
    if (parts.length !== 3 || parts[0] !== "scrypt") return false;
    const expected = Buffer.from(parts[2], "hex");
    if (expected.length !== 64) return false;
    const actual = await scryptAsync(password, parts[1], 64);
    return crypto.timingSafeEqual(expected, actual);
  } catch (_) {
    return false;
  }
}

function createToken(user) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: String(user.id),
    username: user.username,
    iat: now,
    exp: now + 7 * 24 * 60 * 60
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", process.env.JWT_SECRET)
    .update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function verifyToken(token) {
  if (typeof token !== "string" || token.length > 4096) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [encoded, supplied] = parts;
  const expected = crypto.createHmac("sha256", process.env.JWT_SECRET)
    .update(encoded).digest();
  const actual = Buffer.from(supplied, "base64url");
  if (actual.length !== expected.length ||
      !crypto.timingSafeEqual(actual, expected)) return null;
  try {
    const payload = JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8")
    );
    if (!payload.sub || !Number.isInteger(payload.exp) ||
        payload.exp <= Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

async function requireAuth(req, res, next) {
  if (!authReady(res)) return;
  const match = (req.get("authorization") || "").match(/^Bearer\s+(.+)$/i);
  if (!match) return res.status(401).json({ error: "Authentication required." });
  const payload = verifyToken(match[1]);
  if (!payload) {
    return res.status(401).json({ error: "Invalid or expired access token." });
  }

  try {
    const result = await pool.query(
      `SELECT id, username, email, role, account_status, created_at
       FROM users WHERE id::text = $1 LIMIT 1`,
      [String(payload.sub)]
    );
    if (!result.rows.length) {
      return res.status(401).json({ error: "Account not found." });
    }
    const user = result.rows[0];
    if (String(user.account_status).toLowerCase() !== "active") {
      return res.status(403).json({ error: "This account is not active." });
    }
    req.user = user;
    next();
  } catch (e) {
    next(e);
  }
}

function requireAdmin(req, res, next) {
  if (String(req.user?.role || "").toLowerCase() !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
  }
  next();
}

// Moderators receive only explicitly granted tools. Admins retain full access.
function requireModeratorPermission(permission) {
  return async function (req, res, next) {
    if (String(req.user?.role || "").toLowerCase() === "admin") return next();
    try {
      const result = await pool.query(
        `SELECT permissions FROM ft_moderators
         WHERE user_id=$1 AND active=TRUE LIMIT 1`,
        [String(req.user.id)]
      );
      const permissions = result.rows[0]?.permissions || {};
      if (permissions[permission] === true) return next();
      return res.status(403).json({
        error: "You do not have permission to use this moderation tool."
      });
    } catch (error) {
      next(error);
    }
  };
}

function publicUser(user) {
  return {
    id: String(user.id),
    username: user.username,
    email: user.email,
    role: user.role,
    account_status: user.account_status,
    created_at: user.created_at
  };
}

function checkFileSignature(buffer, type) {
  if (!buffer || buffer.length < 12) return false;
  if (type === "image/jpeg") {
    return buffer[0] === 255 && buffer[1] === 216 && buffer[2] === 255;
  }
  if (type === "image/png") {
    return buffer.subarray(0, 8).equals(
      Buffer.from([137,80,78,71,13,10,26,10])
    );
  }
  if (type === "image/gif") {
    return ["GIF87a", "GIF89a"].includes(
      buffer.subarray(0, 6).toString("ascii")
    );
  }
  if (type === "image/webp") {
    return buffer.subarray(0, 4).toString("ascii") === "RIFF" &&
      buffer.subarray(8, 12).toString("ascii") === "WEBP";
  }
  if (type === "video/mp4" || type === "video/quicktime") {
    return buffer.subarray(4, 8).toString("ascii") === "ftyp";
  }
  if (type === "video/webm") {
    return buffer.subarray(0, 4).equals(Buffer.from([26,69,223,163]));
  }
  return false;
}

function sendCloudinaryUpload(buffer, mimetype) {
  return new Promise((resolve, reject) => {
    const resourceType = mimetype.startsWith("video/") ? "video" : "image";
    const stream = cloudinary.uploader.upload_stream(
      {
        folder: "freetube", resource_type: resourceType,
        quality: "auto:good", fetch_format: "auto",
        ...(resourceType === "image"
          ? { transformation: [{ width: 1920, height: 1920, crop: "limit" }] }
          : { transformation: [{ width: 1280, crop: "limit" }] })
      },
      (error, result) => {
        if (error) return reject(error);
        resolve({
          url: result.secure_url,
          public_id: result.public_id,
          resource_type: result.resource_type,
          bytes: result.bytes
        });
      }
    );
    stream.end(buffer);
  });
}

async function initializeDatabase() {
  if (!pool) return;

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ft_profiles (
      user_id TEXT PRIMARY KEY,
      display_name VARCHAR(80),
      bio VARCHAR(500),
      avatar_url TEXT,
      cover_url TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ft_posts (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      content TEXT NOT NULL DEFAULT '',
      media_url TEXT,
      media_type VARCHAR(20),
      media_public_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ft_likes (
      post_id BIGINT NOT NULL REFERENCES ft_posts(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(post_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS ft_comments (
      id BIGSERIAL PRIMARY KEY,
      post_id BIGINT NOT NULL REFERENCES ft_posts(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      content VARCHAR(2000) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ft_messages (
      id BIGSERIAL PRIMARY KEY,
      sender_id TEXT NOT NULL,
      recipient_id TEXT NOT NULL,
      content VARCHAR(5000) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      read_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS ft_notifications (
      id BIGSERIAL PRIMARY KEY,
      recipient_id TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      type VARCHAR(30) NOT NULL,
      post_id BIGINT,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      read_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS ft_follows (
      follower_id TEXT NOT NULL,
      following_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(follower_id, following_id),
      CHECK(follower_id <> following_id)
    );

    CREATE TABLE IF NOT EXISTS ft_post_reports (
      id BIGSERIAL PRIMARY KEY,
      post_id BIGINT NOT NULL REFERENCES ft_posts(id) ON DELETE CASCADE,
      reporter_id TEXT NOT NULL,
      reason VARCHAR(500) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','reviewed','dismissed')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(post_id, reporter_id)
    );

    CREATE TABLE IF NOT EXISTS ft_post_views (
      post_id BIGINT NOT NULL REFERENCES ft_posts(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      view_day DATE NOT NULL DEFAULT CURRENT_DATE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(post_id, user_id, view_day)
    );

    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS location VARCHAR(120);
    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS hometown VARCHAR(120);
    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS birthday DATE;
    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS work VARCHAR(160);
    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS education VARCHAR(160);
    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS blue_badge_status VARCHAR(20) NOT NULL DEFAULT 'none';
    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS blue_badge_expires_at TIMESTAMPTZ;
    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS blue_badge_duration_months INTEGER;

    ALTER TABLE ft_posts ADD COLUMN IF NOT EXISTS moderation_status VARCHAR(20) NOT NULL DEFAULT 'approved';
    ALTER TABLE ft_posts ADD COLUMN IF NOT EXISTS moderation_result JSONB;
    ALTER TABLE ft_posts ADD COLUMN IF NOT EXISTS reaction_counts JSONB NOT NULL DEFAULT '{}'::jsonb;

    -- Photos never require moderation. Convert old pending photo posts to approved.
    UPDATE ft_posts SET moderation_status='approved'
      WHERE LOWER(COALESCE(media_type,''))='image' AND moderation_status='pending';

    ALTER TABLE ft_messages ADD COLUMN IF NOT EXISTS media_url TEXT;
    ALTER TABLE ft_messages ADD COLUMN IF NOT EXISTS media_type VARCHAR(20);
    ALTER TABLE ft_messages ADD COLUMN IF NOT EXISTS media_public_id TEXT;
    CREATE INDEX IF NOT EXISTS ft_messages_expiry_idx ON ft_messages(created_at);

    CREATE TABLE IF NOT EXISTS ft_post_reactions (
      post_id BIGINT NOT NULL REFERENCES ft_posts(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      reaction VARCHAR(16) NOT NULL CHECK (reaction IN ('love','haha','sad','angry')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(post_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS ft_friend_requests (
      id BIGSERIAL PRIMARY KEY,
      sender_id TEXT NOT NULL,
      recipient_id TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined','cancelled')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(sender_id,recipient_id), CHECK(sender_id <> recipient_id)
    );
    CREATE TABLE IF NOT EXISTS ft_friends (
      user_id TEXT NOT NULL,
      friend_id TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(user_id,friend_id), CHECK(user_id <> friend_id)
    );
    CREATE TABLE IF NOT EXISTS ft_admin_notices (
      id BIGSERIAL PRIMARY KEY,
      admin_id TEXT NOT NULL,
      title VARCHAR(160) NOT NULL,
      body VARCHAR(3000) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS ft_moderators (
      user_id TEXT PRIMARY KEY,
      username VARCHAR(50) NOT NULL,
      permissions JSONB NOT NULL DEFAULT '{"moderation":true,"reports":false}'::jsonb,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      granted_by TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS ft_moderators_active_idx
      ON ft_moderators(active);
    CREATE TABLE IF NOT EXISTS ft_monetization (
      user_id TEXT PRIMARY KEY,
      enabled BOOLEAN NOT NULL DEFAULT FALSE,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS ft_manual_payments (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      purpose VARCHAR(30) NOT NULL CHECK(purpose IN ('blue_badge','monetization','other')),
      amount NUMERIC(12,2) NOT NULL CHECK(amount > 0),
      duration_months INTEGER NOT NULL DEFAULT 1 CHECK(duration_months IN (1,3,6,12)),
      currency VARCHAR(8) NOT NULL DEFAULT 'BDT',
      method VARCHAR(40) NOT NULL,
      transaction_ref VARCHAR(160) NOT NULL,
      payer_account VARCHAR(160) NOT NULL DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
      admin_note VARCHAR(500),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      UNIQUE(method,transaction_ref)
    );
    CREATE TABLE IF NOT EXISTS ft_payment_methods (
      id BIGSERIAL PRIMARY KEY,
      code VARCHAR(50) NOT NULL UNIQUE,
      name VARCHAR(80) NOT NULL,
      region VARCHAR(20) NOT NULL DEFAULT 'global' CHECK(region IN ('bangladesh','india','global')),
      currency VARCHAR(8) NOT NULL DEFAULT 'BDT',
      price_amount NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(price_amount >= 0),
      account_name VARCHAR(160) NOT NULL DEFAULT '',
      account_details VARCHAR(500) NOT NULL DEFAULT '',
      instructions VARCHAR(1500) NOT NULL DEFAULT '',
      qr_image_url TEXT NOT NULL DEFAULT '',
      enabled BOOLEAN NOT NULL DEFAULT FALSE,
      sort_order INTEGER NOT NULL DEFAULT 100,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE ft_manual_payments ADD COLUMN IF NOT EXISTS duration_months INTEGER NOT NULL DEFAULT 1;
    ALTER TABLE ft_payment_methods ADD COLUMN IF NOT EXISTS price_1_month NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(price_1_month >= 0);
    ALTER TABLE ft_payment_methods ADD COLUMN IF NOT EXISTS price_3_months NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(price_3_months >= 0);
    ALTER TABLE ft_payment_methods ADD COLUMN IF NOT EXISTS price_6_months NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(price_6_months >= 0);
    ALTER TABLE ft_payment_methods ADD COLUMN IF NOT EXISTS price_12_months NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK(price_12_months >= 0);

    CREATE TABLE IF NOT EXISTS ft_password_resets (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS ft_reactions_post_idx ON ft_post_reactions(post_id);
    CREATE INDEX IF NOT EXISTS ft_friend_requests_recipient_idx ON ft_friend_requests(recipient_id,status,created_at DESC);
    CREATE INDEX IF NOT EXISTS ft_manual_payments_status_idx ON ft_manual_payments(status,created_at DESC);

    CREATE INDEX IF NOT EXISTS ft_posts_created_idx
      ON ft_posts(created_at DESC);
    CREATE INDEX IF NOT EXISTS ft_comments_post_idx
      ON ft_comments(post_id, created_at);
    CREATE INDEX IF NOT EXISTS ft_messages_pair_idx
      ON ft_messages(sender_id, recipient_id, created_at);
    CREATE INDEX IF NOT EXISTS ft_notifications_recipient_idx
      ON ft_notifications(recipient_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS ft_follows_following_idx
      ON ft_follows(following_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS ft_reports_status_idx
      ON ft_post_reports(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS ft_post_views_post_idx
      ON ft_post_views(post_id);

    -- Tournament tables are additive. Existing Social App tables/data are untouched.
    CREATE TABLE IF NOT EXISTS ft_tournament_profiles (
      user_id TEXT PRIMARY KEY,
      free_fire_name VARCHAR(80) NOT NULL DEFAULT '',
      free_fire_uid VARCHAR(40) NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ft_tournaments (
      id BIGSERIAL PRIMARY KEY,
      title VARCHAR(120) NOT NULL,
      description VARCHAR(2000) NOT NULL DEFAULT '',
      mode VARCHAR(20) NOT NULL DEFAULT 'Squad'
        CHECK (mode IN ('Solo','Duo','Squad')),
      map_name VARCHAR(80) NOT NULL DEFAULT 'Bermuda',
      entry_fee NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (entry_fee >= 0),
      prize_pool NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (prize_pool >= 0),
      prize_mode VARCHAR(20) NOT NULL DEFAULT 'fixed'
        CHECK (prize_mode IN ('fixed','dynamic')),
      prize_percentage NUMERIC(5,2) NOT NULL DEFAULT 0
        CHECK (prize_percentage >= 0 AND prize_percentage <= 100),
      max_players INTEGER NOT NULL DEFAULT 100 CHECK (max_players > 0),
      banner_url TEXT NOT NULL DEFAULT '',
      scheduled_at TIMESTAMPTZ,
      status VARCHAR(20) NOT NULL DEFAULT 'upcoming'
        CHECK (status IN ('upcoming','live','completed','cancelled')),
      created_by TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS ft_tournaments_status_date_idx
      ON ft_tournaments(status, scheduled_at);

    CREATE TABLE IF NOT EXISTS ft_tournament_registrations (
      id BIGSERIAL PRIMARY KEY,
      tournament_id BIGINT NOT NULL REFERENCES ft_tournaments(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'registered'
        CHECK (status IN ('registered','cancelled','disqualified')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(tournament_id, user_id)
    );

    CREATE INDEX IF NOT EXISTS ft_tournament_registrations_tournament_idx
      ON ft_tournament_registrations(tournament_id, created_at);

    -- Tournament Admin/User connection: all additions are isolated to tournament tables.
    ALTER TABLE ft_tournaments ADD COLUMN IF NOT EXISTS tournament_type VARCHAR(30) NOT NULL DEFAULT 'br-match';
    ALTER TABLE ft_tournaments ADD COLUMN IF NOT EXISTS registration_open BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE ft_tournaments ADD COLUMN IF NOT EXISTS team_limit INTEGER;
    CREATE TABLE IF NOT EXISTS ft_tournament_teams (
      id BIGSERIAL PRIMARY KEY,
      tournament_id BIGINT NOT NULL REFERENCES ft_tournaments(id) ON DELETE CASCADE,
      captain_user_id TEXT NOT NULL,
      team_name VARCHAR(100) NOT NULL,
      players JSONB NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','disqualified')),
      admin_note VARCHAR(500) NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(tournament_id,captain_user_id)
    );
    CREATE INDEX IF NOT EXISTS ft_tournament_teams_list_idx ON ft_tournament_teams(tournament_id,status,created_at);
    CREATE TABLE IF NOT EXISTS ft_tournament_knockout (
      id BIGSERIAL PRIMARY KEY,
      tournament_id BIGINT NOT NULL REFERENCES ft_tournaments(id) ON DELETE CASCADE,
      round_number INTEGER NOT NULL CHECK(round_number BETWEEN 1 AND 6),
      round_name VARCHAR(40) NOT NULL,
      team_id BIGINT NOT NULL REFERENCES ft_tournament_teams(id) ON DELETE CASCADE,
      position INTEGER NOT NULL DEFAULT 0,
      score NUMERIC(12,2) NOT NULL DEFAULT 0,
      qualified BOOLEAN NOT NULL DEFAULT FALSE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(tournament_id,round_number,team_id)
    );
    CREATE INDEX IF NOT EXISTS ft_tournament_knockout_round_idx ON ft_tournament_knockout(tournament_id,round_number,position);
    CREATE TABLE IF NOT EXISTS ft_tournament_payment_settings (
      id SMALLINT PRIMARY KEY DEFAULT 1 CHECK(id=1),
      methods JSONB NOT NULL DEFAULT '[{"code":"bkash","name":"bKash","enabled":false,"account":"","instructions":""},{"code":"nagad","name":"Nagad","enabled":false,"account":"","instructions":""},{"code":"rocket","name":"Rocket","enabled":false,"account":"","instructions":""},{"code":"binance","name":"Binance","enabled":false,"account":"","instructions":""},{"code":"redotpay","name":"RedotPay","enabled":false,"account":"","instructions":""}]'::jsonb,
      updated_by TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    INSERT INTO ft_tournament_payment_settings(id) VALUES(1) ON CONFLICT(id) DO NOTHING;
  `);

  const defaultPaymentMethods = [
    ['bkash','bKash','bangladesh','BDT',10],
    ['nagad','Nagad','bangladesh','BDT',20],
    ['rocket','Rocket','bangladesh','BDT',30],
    ['upi','UPI','india','INR',40],
    ['phonepe','PhonePe','india','INR',50],
    ['google_pay','Google Pay','india','INR',60],
    ['paytm','Paytm','india','INR',70],
    ['binance','Binance Crypto','global','USDT',80],
    ['redotpay','RedotPay','global','USDT',90]
  ];
  for (const [code,name,region,currency,sortOrder] of defaultPaymentMethods) {
    await pool.query(
      `INSERT INTO ft_payment_methods(code,name,region,currency,sort_order,enabled)
       VALUES($1,$2,$3,$4,$5,FALSE) ON CONFLICT(code) DO NOTHING`,
      [code,name,region,currency,sortOrder]
    );
  }


  // Tournament wallet and match history: additive schema; never alters Social App data.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ft_tournament_wallets (
      user_id TEXT PRIMARY KEY,
      balance NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (balance >= 0),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS ft_tournament_transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      type VARCHAR(20) NOT NULL CHECK (type IN ('deposit','withdrawal','entry_fee','prize')),
      amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
      currency VARCHAR(8) NOT NULL DEFAULT 'BDT',
      payment_method VARCHAR(80) NOT NULL DEFAULT '',
      transaction_ref VARCHAR(160) NOT NULL DEFAULT '',
      destination VARCHAR(180) NOT NULL DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','rejected','completed')),
      admin_note VARCHAR(500) NOT NULL DEFAULT '',
      reviewed_by TEXT,
      reviewed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS ft_tournament_tx_user_idx
      ON ft_tournament_transactions(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS ft_tournament_tx_status_idx
      ON ft_tournament_transactions(status, created_at DESC);
    CREATE TABLE IF NOT EXISTS ft_tournament_game_history (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      tournament_id BIGINT REFERENCES ft_tournaments(id) ON DELETE SET NULL,
      match_name VARCHAR(140) NOT NULL,
      game_mode VARCHAR(40) NOT NULL DEFAULT '',
      played_at TIMESTAMPTZ,
      player_or_team VARCHAR(120) NOT NULL DEFAULT '',
      rank INTEGER,
      kills INTEGER NOT NULL DEFAULT 0 CHECK (kills >= 0),
      result VARCHAR(120) NOT NULL DEFAULT '',
      prize_amount NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (prize_amount >= 0),
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','verified','rejected')),
      verified_by TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS ft_tournament_history_user_idx
      ON ft_tournament_game_history(user_id, played_at DESC);
  `);

  const adminEmail = cleanText(process.env.ADMIN_EMAIL, 255).toLowerCase();
  if (adminEmail) {
    const result = await pool.query(
      "UPDATE users SET role='admin' WHERE LOWER(email)=$1 RETURNING id",
      [adminEmail]
    );
    if (!result.rowCount) {
      console.warn("ADMIN_EMAIL does not match an existing user.");
    }
  }
  console.log("FreeTube tables initialized.");
}

app.get("/", (req, res) => {
  res.json({ name: "FreeTube Backend API", status: "running", version: "3.1.0" });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    databaseConfigured: Boolean(pool),
    cloudinaryConfigured
  });
});

app.get("/api/health/database", async (req, res, next) => {
  if (!pool) return res.status(503).json({ status: "not_configured" });
  try {
    await pool.query("SELECT 1");
    res.json({ status: "connected" });
  } catch (e) {
    next(e);
  }
});

app.post("/api/auth/register", async (req, res, next) => {
  if (!authReady(res)) return;
  let client;

  try {
    const fullName = cleanText(
      req.body.full_name || req.body.fullName || req.body.name, 80
    );
    const email = cleanText(req.body.email, 255).toLowerCase();
    const password = typeof req.body.password === "string"
      ? req.body.password : "";

    if (fullName.length < 2) {
      return res.status(400).json({ error: "Full name must contain at least 2 characters." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }
    const bytes = Buffer.byteLength(password, "utf8");
    if (bytes < 8 || bytes > 128) {
      return res.status(400).json({ error: "Password must be 8-128 bytes long." });
    }

    const passwordHash = await hashPassword(password);
    const base = makeUsernameBase(fullName);
    client = await pool.connect();
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [base]);

    const existing = await client.query(
      "SELECT id FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1",
      [email]
    );
    if (existing.rowCount) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "This email is already registered." });
    }

    let user = null;
    for (let i = 0; i < 100; i++) {
      const suffix = i ? String(i + 1) : "";
      const username = suffix
        ? base.slice(0, 50 - suffix.length) + suffix
        : base;

      await client.query("SAVEPOINT username_attempt");
      try {
        const result = await client.query(
          `INSERT INTO users
             (username,email,password_hash,role,account_status)
           VALUES ($1,$2,$3,'creator','active')
           RETURNING id,username,email,role,account_status,created_at`,
          [username, email, passwordHash]
        );
        user = result.rows[0];
        await client.query("RELEASE SAVEPOINT username_attempt");
        break;
      } catch (e) {
        await client.query("ROLLBACK TO SAVEPOINT username_attempt");
        await client.query("RELEASE SAVEPOINT username_attempt");
        if (e.code !== "23505") throw e;

        const duplicateEmail = await client.query(
          "SELECT id FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1",
          [email]
        );
        if (duplicateEmail.rowCount) {
          await client.query("ROLLBACK");
          return res.status(409).json({ error: "This email is already registered." });
        }
      }
    }

    if (!user) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "Could not generate a username." });
    }

    await client.query(
      `INSERT INTO ft_profiles(user_id,display_name)
       VALUES($1,$2)
       ON CONFLICT(user_id) DO NOTHING`,
      [String(user.id), fullName]
    );

    await client.query("COMMIT");
    res.status(201).json({
      message: "Account created successfully.",
      token: createToken(user),
      user: { ...publicUser(user), display_name: fullName }
    });
  } catch (e) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    next(e);
  } finally {
    if (client) client.release();
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  if (!authReady(res)) return;

  try {
    const identifier = cleanText(
      req.body.identifier || req.body.email || req.body.username, 255
    );
    const password = typeof req.body.password === "string"
      ? req.body.password : "";

    if (!identifier || !password) {
      return res.status(400).json({ error: "Enter your email/username and password." });
    }

    const result = await pool.query(
      `SELECT id,username,email,password_hash,role,account_status,created_at
       FROM users
       WHERE LOWER(email)=LOWER($1) OR LOWER(username)=LOWER($1)
       LIMIT 1`,
      [identifier]
    );

    const user = result.rows[0];
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid username/email or password." });
    }
    if (String(user.account_status).toLowerCase() !== "active") {
      return res.status(403).json({ error: "This account is not active." });
    }

    await pool.query(
      `INSERT INTO ft_profiles(user_id,display_name)
       VALUES($1,$2) ON CONFLICT(user_id) DO NOTHING`,
      [String(user.id), user.username]
    );

    res.json({
      message: "Login successful.",
      token: createToken(user),
      user: publicUser(user)
    });
  } catch (e) {
    next(e);
  }
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.get("/api/users/search", requireAuth, async (req, res, next) => {
  try {
    const q = cleanText(req.query.q, 50);
    if (q.length < 2) return res.json({ users: [] });

    const result = await pool.query(
      `SELECT u.id::text AS id,u.username,p.display_name,p.avatar_url
       FROM users u LEFT JOIN ft_profiles p ON p.user_id=u.id::text
       WHERE u.account_status='active'
         AND u.id::text<>$1
         AND LOWER(u.username) LIKE LOWER($2)
       ORDER BY u.username LIMIT 20`,
      [String(req.user.id), `%${q}%`]
    );

    res.json({ users: result.rows });
  } catch (e) {
    next(e);
  }
});

app.get("/api/profile/:username", async (req, res, next) => {
  if (!authReady(res)) return;

  try {
    const result = await pool.query(
      `SELECT u.id::text AS id,u.username,u.email,
              p.display_name,p.bio,p.avatar_url,p.cover_url,p.location,p.hometown,
              p.birthday,p.work,p.education,CASE WHEN p.blue_badge_status='verified' AND p.blue_badge_expires_at IS NOT NULL AND p.blue_badge_expires_at<=NOW() THEN 'expired' ELSE p.blue_badge_status END AS blue_badge_status,p.blue_badge_expires_at,p.blue_badge_duration_months,p.updated_at,u.created_at AS account_created_at
       FROM users u LEFT JOIN ft_profiles p ON p.user_id=u.id::text
       WHERE LOWER(u.username)=LOWER($1)
         AND u.account_status='active'
       LIMIT 1`,
      [cleanText(req.params.username, 50)]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "User not found." });
    }

    const profile = result.rows[0];
    const stats = await pool.query(
      `SELECT
       (SELECT COUNT(*) FROM ft_posts WHERE user_id=$1) AS posts,
       (SELECT COUNT(*) FROM ft_likes l JOIN ft_posts p ON p.id=l.post_id
         WHERE p.user_id=$1) AS likes,
       (SELECT COUNT(*) FROM (SELECT follower_id AS uid FROM ft_follows WHERE following_id=$1 UNION SELECT user_id AS uid FROM ft_friends WHERE friend_id=$1) x) AS followers,
       (SELECT COUNT(*) FROM (SELECT following_id AS uid FROM ft_follows WHERE follower_id=$1 UNION SELECT friend_id AS uid FROM ft_friends WHERE user_id=$1) x) AS following`,
      [String(profile.id)]
    );

    res.json({ profile, stats: stats.rows[0] });
  } catch (e) {
    next(e);
  }
});

app.get("/api/profile/id/:userId", requireAuth, async(req,res,next)=>{
  try {
    const id=cleanText(req.params.userId,100);
    const result=await pool.query(`SELECT u.id::text AS id,u.username,u.email,
      p.display_name,p.bio,p.avatar_url,p.cover_url,p.location,p.hometown,p.birthday,p.work,p.education,CASE WHEN p.blue_badge_status='verified' AND p.blue_badge_expires_at IS NOT NULL AND p.blue_badge_expires_at<=NOW() THEN 'expired' ELSE p.blue_badge_status END AS blue_badge_status,p.blue_badge_expires_at,p.blue_badge_duration_months,p.updated_at,
      u.created_at AS account_created_at
      FROM users u LEFT JOIN ft_profiles p ON p.user_id=u.id::text
      WHERE u.id::text=$1 AND u.account_status='active' LIMIT 1`,[id]);
    if(!result.rowCount) return res.status(404).json({error:"User not found."});
    const profile=result.rows[0];
    const stats=await pool.query(`SELECT
      (SELECT COUNT(*) FROM ft_posts WHERE user_id=$1) AS posts,
      (SELECT COUNT(*) FROM ft_likes l JOIN ft_posts p ON p.id=l.post_id WHERE p.user_id=$1) AS likes,
      (SELECT COUNT(*) FROM (SELECT follower_id AS uid FROM ft_follows WHERE following_id=$1 UNION SELECT user_id AS uid FROM ft_friends WHERE friend_id=$1) x) AS followers,
      (SELECT COUNT(*) FROM (SELECT following_id AS uid FROM ft_follows WHERE follower_id=$1 UNION SELECT friend_id AS uid FROM ft_friends WHERE user_id=$1) x) AS following`,[id]);
    res.json({profile,stats:stats.rows[0]});
  } catch(e){next(e);}
});

app.put("/api/profile", requireAuth, async (req, res, next) => {
  try {
    const displayName = cleanText(req.body.display_name, 80);
    const bio = cleanText(req.body.bio, 500);
    const avatarUrl = cleanText(req.body.avatar_url, 2000);
    const coverUrl = cleanText(req.body.cover_url, 2000);
    const location = cleanText(req.body.location, 120);
    const hometown = cleanText(req.body.hometown, 120);
    const birthday = cleanText(req.body.birthday, 10);
    const work = cleanText(req.body.work, 160);
    const education = cleanText(req.body.education, 160);

    await pool.query(
      `INSERT INTO ft_profiles(user_id,display_name,bio,avatar_url,cover_url,location,hometown,birthday,work,education,updated_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
       ON CONFLICT(user_id) DO UPDATE SET
         display_name=EXCLUDED.display_name,
         bio=EXCLUDED.bio,
         avatar_url=COALESCE(EXCLUDED.avatar_url,ft_profiles.avatar_url),
         cover_url=COALESCE(EXCLUDED.cover_url,ft_profiles.cover_url),
         location=EXCLUDED.location,hometown=EXCLUDED.hometown,birthday=EXCLUDED.birthday,
         work=EXCLUDED.work,education=EXCLUDED.education,updated_at=NOW()`,
      [String(req.user.id),displayName || req.user.username,bio,avatarUrl || null,coverUrl || null,
       location || null,hometown || null,(birthday && /^\d{4}-\d{2}-\d{2}$/.test(birthday)) ? birthday : null,work || null,education || null]
    );

    res.json({ message: "Profile updated." });
  } catch (e) {
    next(e);
  }
});

app.post("/api/media/upload", requireAuth, (req, res, next) => {
  if (!cloudinaryConfigured) {
    return res.status(503).json({ error: "Cloudinary is not configured." });
  }

  upload.single("file")(req, res, async error => {
    if (error) return next(error);
    try {
      if (!req.file) {
        return res.status(400).json({ error: "Select an image or video." });
      }
      if (!checkFileSignature(req.file.buffer, req.file.mimetype)) {
        return res.status(400).json({ error: "The file content does not match its type." });
      }

      const media = await sendCloudinaryUpload(
        req.file.buffer, req.file.mimetype
      );

      res.status(201).json({ media });
    } catch (e) {
      next(e);
    }
  });
});

app.get("/api/posts", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT p.id::text AS id,p.user_id,p.content,p.media_url,p.media_type,
              p.created_at,u.username,pr.display_name,pr.avatar_url,
              CASE WHEN pr.blue_badge_status='verified'
                     AND pr.blue_badge_expires_at IS NOT NULL
                     AND pr.blue_badge_expires_at > NOW()
                   THEN 'verified' ELSE 'none' END AS blue_badge_status,
              (SELECT COUNT(*) FROM ft_post_reactions r WHERE r.post_id=p.id) AS reaction_count,
              (SELECT COALESCE(jsonb_object_agg(rc.reaction,rc.cnt),'{}'::jsonb)
                 FROM (SELECT reaction,COUNT(*)::int AS cnt FROM ft_post_reactions
                       WHERE post_id=p.id GROUP BY reaction) rc) AS reaction_counts,
              (SELECT COUNT(*) FROM ft_post_reactions r WHERE r.post_id=p.id) AS like_count,
              (SELECT COUNT(*) FROM ft_comments c WHERE c.post_id=p.id) AS comment_count,
              (SELECT COUNT(*) FROM ft_post_views v WHERE v.post_id=p.id) AS view_count,
              EXISTS(SELECT 1 FROM ft_post_reactions r
                     WHERE r.post_id=p.id AND r.user_id=$1) AS liked
       FROM ft_posts p
       JOIN users u ON u.id::text=p.user_id
       LEFT JOIN ft_profiles pr ON pr.user_id=p.user_id
       WHERE u.account_status='active' AND p.moderation_status='approved'
       ORDER BY p.created_at DESC LIMIT 100`,
      [String(req.user.id)]
    );

    res.json({ posts: result.rows });
  } catch (e) {
    next(e);
  }
});

app.post("/api/posts", requireAuth, async (req, res, next) => {
  try {
    const content = cleanText(req.body.content, 5000);
    const mediaUrl = cleanText(req.body.media_url, 2000);
    const mediaType = cleanText(req.body.media_type, 20);
    const publicId = cleanText(req.body.media_public_id, 500);

    if (!content && !mediaUrl) {
      return res.status(400).json({ error: "Write something or upload media." });
    }
    if (mediaUrl && !mediaUrl.startsWith("https://res.cloudinary.com/")) {
      return res.status(400).json({ error: "Media URL must be a Cloudinary HTTPS URL." });
    }
    if (mediaUrl && !["image", "video"].includes(mediaType)) {
      return res.status(400).json({ error: "Invalid media type." });
    }

    // Only video posts require admin approval. Photos and text-only posts publish immediately.
    const moderationStatus = mediaUrl && mediaType === "video" ? "pending" : "approved";
    const result = await pool.query(
      `INSERT INTO ft_posts(user_id,content,media_url,media_type,media_public_id,moderation_status)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
      [String(req.user.id),content,mediaUrl || null,mediaType || null,publicId || null,moderationStatus]
    );
    if (moderationStatus === "pending") {
      await pool.query(
        `INSERT INTO ft_notifications(recipient_id,actor_id,type,post_id,message)
         SELECT id::text,$1,'moderation_pending',$2,$3 FROM users WHERE LOWER(role)='admin'`,
        [String(req.user.id),result.rows[0].id,`A video post from ${req.user.username} is waiting for moderation.`]
      );
    }
    res.status(201).json({
      message: moderationStatus === "pending" ? "Post submitted and is awaiting moderation." : "Post published.",
      post: result.rows[0]
    });
  } catch (e) {
    next(e);
  }
});

app.put("/api/posts/:id", requireAuth, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const content = cleanText(req.body.content, 5000);
    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({ error: "Invalid post ID." });
    }

    const existing = await pool.query(
      "SELECT id,media_url FROM ft_posts WHERE id=$1 AND user_id=$2",
      [id, String(req.user.id)]
    );

    if (!existing.rowCount) {
      const anyPost = await pool.query("SELECT id FROM ft_posts WHERE id=$1", [id]);
      return res.status(anyPost.rowCount ? 403 : 404).json({
        error: anyPost.rowCount ? "You can only edit your own posts." : "Post not found."
      });
    }

    if (!content && !existing.rows[0].media_url) {
      return res.status(400).json({ error: "A post cannot be empty." });
    }

    const result = await pool.query(
      "UPDATE ft_posts SET content=$1 WHERE id=$2 RETURNING *",
      [content, id]
    );

    res.json({ message: "Post updated.", post: result.rows[0] });
  } catch (e) {
    next(e);
  }
});

// Delete exactly one post, its dependent database rows, and only its own Cloudinary asset.
// The database transaction commits before Cloudinary cleanup; cleanup failures are reported
// without risking deletion of any other media asset.
async function deleteSinglePost(postId) {
  const client = await pool.connect();
  let post = null;
  try {
    await client.query("BEGIN");
    const locked = await client.query(
      `SELECT id,user_id,media_public_id,media_type
       FROM ft_posts WHERE id=$1 FOR UPDATE`,
      [postId]
    );
    if (!locked.rowCount) {
      await client.query("ROLLBACK");
      return { found: false };
    }
    post = locked.rows[0];

    // Notifications do not have an ON DELETE CASCADE constraint. Remove only
    // notifications explicitly linked to this exact post ID.
    await client.query("DELETE FROM ft_notifications WHERE post_id=$1", [postId]);

    // Likes, reactions, comments, views and reports use ON DELETE CASCADE.
    await client.query("DELETE FROM ft_posts WHERE id=$1", [postId]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }

  let mediaDeleted = true;
  if (post.media_public_id) {
    if (!cloudinaryConfigured) {
      mediaDeleted = false;
    } else {
      try {
        const resourceType = String(post.media_type || "").toLowerCase() === "video" ? "video" : "image";
        await cloudinary.uploader.destroy(post.media_public_id, {
          resource_type: resourceType,
          invalidate: true
        });
      } catch (error) {
        mediaDeleted = false;
        console.error("Post media cleanup failed for post", String(postId), error.message);
      }
    }
  }
  return { found: true, mediaDeleted };
}

app.delete("/api/posts/:id", requireAuth, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({ error: "Invalid post ID." });
    }

    const admin = String(req.user.role).toLowerCase() === "admin";
    const owner = await pool.query("SELECT user_id FROM ft_posts WHERE id=$1", [id]);
    if (!owner.rowCount) return res.status(404).json({ error: "Post not found." });
    if (!admin && String(owner.rows[0].user_id) !== String(req.user.id)) {
      return res.status(403).json({ error: "You can only delete your own posts." });
    }

    const result = await deleteSinglePost(id);
    if (!result.found) return res.status(404).json({ error: "Post not found." });
    res.json({
      message: "Post deleted.",
      id: String(id),
      media_deleted: result.mediaDeleted,
      warning: result.mediaDeleted ? null : "The post was deleted, but its Cloudinary media could not be confirmed deleted."
    });
  } catch (e) {
    next(e);
  }
});

app.post("/api/posts/:id/view", requireAuth, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({ error: "Invalid post ID." });
    }

    const inserted = await pool.query(
      `INSERT INTO ft_post_views(post_id,user_id,view_day)
       SELECT id,$2,CURRENT_DATE FROM ft_posts WHERE id=$1
       ON CONFLICT(post_id,user_id,view_day) DO NOTHING
       RETURNING post_id`,
      [id, String(req.user.id)]
    );

    const exists = await pool.query("SELECT id FROM ft_posts WHERE id=$1", [id]);
    if (!exists.rowCount) return res.status(404).json({ error: "Post not found." });

    const count = await pool.query(
      "SELECT COUNT(*) FROM ft_post_views WHERE post_id=$1", [id]
    );

    res.json({
      post_id: String(id),
      viewed_today: inserted.rowCount > 0,
      view_count: Number(count.rows[0].count)
    });
  } catch (e) {
    next(e);
  }
});

// Backward-compatible route: the old Like action now means Love reaction.
// New clients should use POST /api/posts/:id/reaction with love|haha|sad|angry.
app.post("/api/posts/:id/like", requireAuth, async (req, res, next) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isSafeInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid post ID." });
  try {
    const post = await pool.query("SELECT id,user_id FROM ft_posts WHERE id=$1 AND moderation_status='approved'", [id]);
    if (!post.rowCount) return res.status(404).json({ error: "Post not found." });
    const userId = String(req.user.id);
    const existing = await pool.query("SELECT reaction FROM ft_post_reactions WHERE post_id=$1 AND user_id=$2", [id,userId]);
    let reaction = "love";
    if (existing.rowCount && existing.rows[0].reaction === "love") {
      await pool.query("DELETE FROM ft_post_reactions WHERE post_id=$1 AND user_id=$2", [id,userId]);
      reaction = null;
    } else {
      await pool.query(`INSERT INTO ft_post_reactions(post_id,user_id,reaction) VALUES($1,$2,'love')
        ON CONFLICT(post_id,user_id) DO UPDATE SET reaction='love',created_at=NOW()`, [id,userId]);
      if (String(post.rows[0].user_id) !== userId) await notifyUser(post.rows[0].user_id,userId,'reaction',`${req.user.username} loved your post.`,id);
    }
    const counts = await pool.query("SELECT reaction,COUNT(*)::int AS count FROM ft_post_reactions WHERE post_id=$1 GROUP BY reaction", [id]);
    const reactionCounts = Object.fromEntries(counts.rows.map(x=>[x.reaction,x.count]));
    res.json({ liked: reaction === "love", reaction, like_count: counts.rows.reduce((n,x)=>n+x.count,0), reaction_count: counts.rows.reduce((n,x)=>n+x.count,0), reaction_counts: reactionCounts });
  } catch (e) { next(e); }
});

app.get("/api/posts/:id/comments", async (req, res, next) => {
  if (!authReady(res)) return;
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({ error: "Invalid post ID." });
    }

    const result = await pool.query(
      `SELECT c.id,c.post_id,c.user_id,c.content,c.created_at,
              u.username,p.display_name,p.avatar_url,
              CASE WHEN p.blue_badge_status='verified'
                     AND p.blue_badge_expires_at IS NOT NULL
                     AND p.blue_badge_expires_at > NOW()
                   THEN 'verified' ELSE 'none' END AS blue_badge_status
       FROM ft_comments c JOIN users u ON u.id::text=c.user_id
       LEFT JOIN ft_profiles p ON p.user_id=c.user_id
       WHERE c.post_id=$1 ORDER BY c.id ASC LIMIT 100`,
      [id]
    );
    res.json({ comments: result.rows });
  } catch (e) {
    next(e);
  }
});

app.post("/api/posts/:id/comments", requireAuth, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const content = cleanText(req.body.content, 2000);
    if (!Number.isSafeInteger(id) || id <= 0 || !content) {
      return res.status(400).json({ error: "A valid post and comment are required." });
    }

    const post = await pool.query("SELECT user_id FROM ft_posts WHERE id=$1", [id]);
    if (!post.rowCount) return res.status(404).json({ error: "Post not found." });

    const result = await pool.query(
      `INSERT INTO ft_comments(post_id,user_id,content)
       VALUES($1,$2,$3) RETURNING *`,
      [id, String(req.user.id), content]
    );

    if (String(post.rows[0].user_id) !== String(req.user.id)) {
      await pool.query(
        `INSERT INTO ft_notifications(recipient_id,actor_id,type,post_id,message)
         VALUES($1,$2,'comment',$3,$4)`,
        [
          String(post.rows[0].user_id),
          String(req.user.id),
          id,
          `${req.user.username} commented on your post.`
        ]
      );
    }

    res.status(201).json({
      message: "Comment added.",
      comment: { ...result.rows[0], username: req.user.username }
    });
  } catch (e) {
    next(e);
  }
});

app.post("/api/users/:userId/follow", requireAuth, async (req, res, next) => {
  try {
    const targetId = cleanText(req.params.userId, 100);
    const myId = String(req.user.id);
    if (!targetId || targetId === myId) {
      return res.status(400).json({ error: "You cannot follow yourself." });
    }

    const target = await pool.query(
      "SELECT id FROM users WHERE id::text=$1 AND account_status='active'",
      [targetId]
    );
    if (!target.rowCount) return res.status(404).json({ error: "User not found." });

    const existing = await pool.query(
      "SELECT 1 FROM ft_follows WHERE follower_id=$1 AND following_id=$2",
      [myId, targetId]
    );

    if (existing.rowCount) {
      await pool.query(
        "DELETE FROM ft_follows WHERE follower_id=$1 AND following_id=$2",
        [myId, targetId]
      );
      return res.json({ following: false, message: "Unfollowed successfully." });
    }

    await pool.query(
      `INSERT INTO ft_follows(follower_id,following_id)
       VALUES($1,$2) ON CONFLICT DO NOTHING`,
      [myId, targetId]
    );

    await pool.query(
      `INSERT INTO ft_notifications(recipient_id,actor_id,type,message)
       VALUES($1,$2,'follow',$3)`,
      [targetId, myId, `${req.user.username} followed you.`]
    );

    res.json({ following: true, message: "Followed successfully." });
  } catch (e) {
    next(e);
  }
});

app.get("/api/users/:userId/followers", async (req, res, next) => {
  if (!authReady(res)) return;
  try {
    const id = cleanText(req.params.userId, 100);
    const result = await pool.query(
      `WITH relations AS (
         SELECT follower_id AS person_id, created_at FROM ft_follows WHERE following_id=$1
         UNION ALL
         SELECT user_id AS person_id, created_at FROM ft_friends WHERE friend_id=$1
       ), unique_relations AS (
         SELECT person_id, MAX(created_at) AS relation_at FROM relations GROUP BY person_id
       )
       SELECT u.id::text AS id,u.username,p.display_name,p.avatar_url
       FROM unique_relations r JOIN users u ON u.id::text=r.person_id
       LEFT JOIN ft_profiles p ON p.user_id=u.id::text
       WHERE u.account_status='active'
       ORDER BY r.relation_at DESC LIMIT 100`, 
      [id]
    );
    res.json({ users: result.rows });
  } catch (e) {
    next(e);
  }
});

app.get("/api/users/:userId/following", async (req, res, next) => {
  if (!authReady(res)) return;
  try {
    const id = cleanText(req.params.userId, 100);
    const result = await pool.query(
      `WITH relations AS (
         SELECT following_id AS person_id, created_at FROM ft_follows WHERE follower_id=$1
         UNION ALL
         SELECT friend_id AS person_id, created_at FROM ft_friends WHERE user_id=$1
       ), unique_relations AS (
         SELECT person_id, MAX(created_at) AS relation_at FROM relations GROUP BY person_id
       )
       SELECT u.id::text AS id,u.username,p.display_name,p.avatar_url
       FROM unique_relations r JOIN users u ON u.id::text=r.person_id
       LEFT JOIN ft_profiles p ON p.user_id=u.id::text
       WHERE u.account_status='active'
       ORDER BY r.relation_at DESC LIMIT 100`, 
      [id]
    );
    res.json({ users: result.rows });
  } catch (e) {
    next(e);
  }
});

app.post("/api/posts/:id/report", requireAuth, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const reason = cleanText(req.body.reason, 500);
    if (!Number.isSafeInteger(id) || id <= 0 || reason.length < 3) {
      return res.status(400).json({ error: "A valid post ID and report reason are required." });
    }

    const post = await pool.query(
      "SELECT id,user_id FROM ft_posts WHERE id=$1", [id]
    );
    if (!post.rowCount) return res.status(404).json({ error: "Post not found." });
    if (String(post.rows[0].user_id) === String(req.user.id)) {
      return res.status(400).json({ error: "You cannot report your own post." });
    }

    try {
      await pool.query(
        `INSERT INTO ft_post_reports(post_id,reporter_id,reason)
         VALUES($1,$2,$3)`,
        [id, String(req.user.id), reason]
      );
    } catch (e) {
      if (e.code === "23505") {
        return res.status(409).json({ error: "You have already reported this post." });
      }
      throw e;
    }

    res.status(201).json({ message: "Report submitted for review." });
  } catch (e) {
    next(e);
  }
});

app.get("/api/messages/:userId", requireAuth, async (req, res, next) => {
  try {
    await purgeExpiredMessages();
    const me = String(req.user.id);
    const other = cleanText(req.params.userId, 100);
    if (!other || other === me) {
      return res.status(400).json({ error: "Invalid conversation user." });
    }

    const account = await pool.query(
      "SELECT id FROM users WHERE id::text=$1 AND account_status='active'",
      [other]
    );
    if (!account.rowCount) return res.status(404).json({ error: "User not found." });

    await pool.query(
      `UPDATE ft_messages SET read_at=NOW()
       WHERE sender_id=$1 AND recipient_id=$2 AND read_at IS NULL`,
      [other, me]
    );

    const result = await pool.query(
      `SELECT id,sender_id,recipient_id,content,media_url,media_type,created_at,read_at
       FROM ft_messages
       WHERE created_at > NOW() - INTERVAL '72 hours'
         AND ((sender_id=$1 AND recipient_id=$2)
          OR (sender_id=$2 AND recipient_id=$1))
       ORDER BY id DESC LIMIT 100`,
      [me, other]
    );

    res.json({ messages: result.rows.reverse() });
  } catch (e) {
    next(e);
  }
});

app.post("/api/messages", requireAuth, async (req, res, next) => {
  try {
    await purgeExpiredMessages();
    const recipientId = cleanText(req.body.recipient_id, 100);
    const content = cleanText(req.body.content, 5000);
    const senderId = String(req.user.id);

    if (!recipientId || recipientId === senderId || !content) {
      return res.status(400).json({ error: "A valid recipient and message are required." });
    }

    const recipient = await pool.query(
      "SELECT id FROM users WHERE id::text=$1 AND account_status='active'",
      [recipientId]
    );
    if (!recipient.rowCount) return res.status(404).json({ error: "Recipient not found." });

    const result = await pool.query(
      `INSERT INTO ft_messages(sender_id,recipient_id,content)
       VALUES($1,$2,$3) RETURNING *`,
      [senderId, recipientId, content]
    );

    await pool.query(
      `INSERT INTO ft_notifications(recipient_id,actor_id,type,message)
       VALUES($1,$2,'message',$3)`,
      [recipientId, senderId, `New message from ${req.user.username}.`]
    );

    res.status(201).json({ message: "Message sent.", item: result.rows[0] });
  } catch (e) {
    next(e);
  }
});

app.get("/api/messages", requireAuth, async (req, res, next) => {
  try {
    await purgeExpiredMessages();
    const me = String(req.user.id);
    const result = await pool.query(
      `WITH cm AS (
         SELECT *,CASE WHEN sender_id=$1 THEN recipient_id ELSE sender_id END AS other_id
         FROM ft_messages WHERE created_at > NOW() - INTERVAL '72 hours'
           AND (sender_id=$1 OR recipient_id=$1)
       ), latest AS (
         SELECT DISTINCT ON(other_id) other_id,id,sender_id,recipient_id,content,media_url,media_type,created_at
         FROM cm ORDER BY other_id,id DESC
       )
       SELECT l.*,u.username,p.display_name,p.avatar_url,
         (SELECT COUNT(*) FROM ft_messages m
          WHERE m.sender_id=l.other_id AND m.recipient_id=$1 AND m.read_at IS NULL)
          AS unread_count
       FROM latest l JOIN users u ON u.id::text=l.other_id
       LEFT JOIN ft_profiles p ON p.user_id=l.other_id
       ORDER BY l.id DESC`,
      [me]
    );

    res.json({ conversations: result.rows });
  } catch (e) {
    next(e);
  }
});

app.get("/api/notifications", requireAuth, async (req, res, next) => {
  try {
    const id = String(req.user.id);
    const result = await pool.query(
      `SELECT n.*,u.username AS actor_username
       FROM ft_notifications n LEFT JOIN users u ON u.id::text=n.actor_id
       WHERE n.recipient_id=$1 ORDER BY n.id DESC LIMIT 100`,
      [id]
    );

    const unread = await pool.query(
      "SELECT COUNT(*) FROM ft_notifications WHERE recipient_id=$1 AND read_at IS NULL",
      [id]
    );

    res.json({
      notifications: result.rows,
      unread_count: Number(unread.rows[0].count)
    });
  } catch (e) {
    next(e);
  }
});

app.patch("/api/notifications/:id/read", requireAuth, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({ error: "Invalid notification ID." });
    }

    const result = await pool.query(
      `UPDATE ft_notifications SET read_at=NOW()
       WHERE id=$1 AND recipient_id=$2 RETURNING id,read_at`,
      [id, String(req.user.id)]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Notification not found." });
    }
    res.json({ notification: result.rows[0] });
  } catch (e) {
    next(e);
  }
});

app.patch("/api/notifications/read-all", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query(
      `UPDATE ft_notifications SET read_at=NOW()
       WHERE recipient_id=$1 AND read_at IS NULL`,
      [String(req.user.id)]
    );
    res.json({
      message: "Notifications marked as read.",
      updated: result.rowCount
    });
  } catch (e) {
    next(e);
  }
});

// ADMIN: dashboard
// Moderator management: only a full Admin can grant, edit or revoke access.
app.get("/api/admin/moderators", requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const result = await pool.query(
      `SELECT m.user_id,u.username,u.email,m.permissions,m.active,
              m.granted_by,m.created_at,m.updated_at,
              grantor.username AS granted_by_username
       FROM ft_moderators m
       LEFT JOIN users u ON u.id::text=m.user_id
       LEFT JOIN users grantor ON grantor.id::text=m.granted_by
       ORDER BY m.created_at DESC`
    );
    res.json({ moderators: result.rows });
  } catch (e) { next(e); }
});

app.post("/api/admin/moderators", requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const username = cleanText(req.body.username,50).replace(/^@/,"");
    const supplied = Array.isArray(req.body.permissions) ? req.body.permissions : ["moderation"];
    const allowed = ["moderation","reports"];
    const permissions = {};
    for (const key of allowed) permissions[key] = supplied.includes(key);
    if (!username) return res.status(400).json({error:"Enter the user's username."});
    if (!permissions.moderation && !permissions.reports) {
      return res.status(400).json({error:"Select at least one moderator permission."});
    }
    const found = await pool.query(
      `SELECT id::text AS id,username,email,role,account_status
       FROM users WHERE LOWER(username)=LOWER($1) LIMIT 1`,
      [username]
    );
    if (!found.rowCount) return res.status(404).json({error:"No user found with that username."});
    const user = found.rows[0];
    if (String(user.role).toLowerCase()==="admin") {
      return res.status(400).json({error:"An Admin does not need a Moderator grant."});
    }
    if (String(user.account_status).toLowerCase()!=="active") {
      return res.status(400).json({error:"This user account is not active."});
    }
    const result = await pool.query(
      `INSERT INTO ft_moderators(user_id,username,permissions,active,granted_by)
       VALUES($1,$2,$3::jsonb,TRUE,$4)
       ON CONFLICT(user_id) DO UPDATE SET username=EXCLUDED.username,
         permissions=EXCLUDED.permissions,active=TRUE,granted_by=EXCLUDED.granted_by,
         updated_at=NOW()
       RETURNING user_id,username,permissions,active,granted_by,created_at,updated_at`,
      [user.id,user.username,JSON.stringify(permissions),String(req.user.id)]
    );
    res.status(201).json({message:"Moderator access saved.",moderator:{...result.rows[0],email:user.email}});
  } catch(e) { next(e); }
});

app.patch("/api/admin/moderators/:userId", requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const userId=cleanText(req.params.userId,100);
    if (req.body.active===false) {
      const r=await pool.query(
        `UPDATE ft_moderators SET active=FALSE,updated_at=NOW()
         WHERE user_id=$1 RETURNING user_id,username,permissions,active`,
        [userId]
      );
      if(!r.rowCount) return res.status(404).json({error:"Moderator not found."});
      return res.json({message:"Moderator access suspended.",moderator:r.rows[0]});
    }
    if (Array.isArray(req.body.permissions)) {
      const allowed=["moderation","reports"], permissions={};
      for(const key of allowed) permissions[key]=req.body.permissions.includes(key);
      if(!permissions.moderation&&!permissions.reports) return res.status(400).json({error:"Select at least one permission, or remove the moderator."});
      const r=await pool.query(
        `UPDATE ft_moderators SET permissions=$2::jsonb,active=TRUE,updated_at=NOW()
         WHERE user_id=$1 RETURNING user_id,username,permissions,active`,
        [userId,JSON.stringify(permissions)]
      );
      if(!r.rowCount) return res.status(404).json({error:"Moderator not found."});
      return res.json({message:"Moderator permissions updated.",moderator:r.rows[0]});
    }
    return res.status(400).json({error:"Provide active:false or a permissions array."});
  } catch(e) { next(e); }
});

app.delete("/api/admin/moderators/:userId", requireAuth, requireAdmin, async(req,res,next) => {
  try {
    const r=await pool.query(
      "DELETE FROM ft_moderators WHERE user_id=$1 RETURNING user_id,username",
      [cleanText(req.params.userId,100)]
    );
    if(!r.rowCount) return res.status(404).json({error:"Moderator not found."});
    res.json({message:"Moderator access removed.",moderator:r.rows[0]});
  } catch(e) { next(e); }
});

app.get("/api/admin/dashboard", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*)::int FROM users) AS total_users,
        (SELECT COUNT(*)::int FROM users WHERE account_status='active') AS active_users,
        (SELECT COUNT(*)::int FROM users WHERE account_status<>'active') AS blocked_users,
        (SELECT COUNT(*)::int FROM ft_posts) AS total_posts,
        (SELECT COUNT(*)::int FROM ft_post_reports WHERE status='pending') AS pending_reports
    `);
    res.json({ stats: result.rows[0] });
  } catch (e) {
    next(e);
  }
});

// ADMIN: search and list users
app.get("/api/admin/users", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const q = cleanText(req.query.q || "", 80).toLowerCase();
    const status = cleanText(req.query.status || "all", 20);
    if (!["all", "active", "blocked"].includes(status)) {
      return res.status(400).json({ error: "Invalid user status filter." });
    }

    const result = await pool.query(
      `SELECT u.id::text AS id,u.username,u.email,u.role,u.account_status,u.created_at,
              p.display_name,p.avatar_url,
              (SELECT COUNT(*)::int FROM ft_posts fp WHERE fp.user_id=u.id::text) AS posts_count
       FROM users u LEFT JOIN ft_profiles p ON p.user_id=u.id::text
       WHERE ($1='' OR LOWER(u.username) LIKE '%'||$1||'%'
                    OR LOWER(u.email) LIKE '%'||$1||'%')
         AND ($2='all'
              OR ($2='active' AND u.account_status='active')
              OR ($2='blocked' AND u.account_status<>'active'))
       ORDER BY u.created_at DESC NULLS LAST LIMIT 200`,
      [q, status]
    );
    res.json({ users: result.rows });
  } catch (e) {
    next(e);
  }
});

// ADMIN: ban or unban a normal user
app.patch("/api/admin/users/:id/status", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const targetId = cleanText(req.params.id, 100);
    const action = cleanText(req.body.action, 20).toLowerCase();

    if (!targetId || !["ban", "unban"].includes(action)) {
      return res.status(400).json({ error: "Provide a valid user ID and ban/unban action." });
    }
    if (targetId === String(req.user.id)) {
      return res.status(400).json({ error: "You cannot ban your own admin account." });
    }

    const target = await pool.query(
      "SELECT id,role FROM users WHERE id::text=$1 LIMIT 1",
      [targetId]
    );
    if (!target.rowCount) return res.status(404).json({ error: "User not found." });
    if (String(target.rows[0].role).toLowerCase() === "admin") {
      return res.status(403).json({ error: "Admin accounts cannot be banned here." });
    }

    const status = action === "ban" ? "banned" : "active";
    const updated = await pool.query(
      `UPDATE users SET account_status=$1
       WHERE id::text=$2
       RETURNING id,username,email,role,account_status,created_at`,
      [status, targetId]
    );

    res.json({
      message: action === "ban" ? "User banned." : "User unbanned.",
      user: updated.rows[0]
    });
  } catch (e) {
    next(e);
  }
});

// ADMIN: pending video posts only. Photos and already-reviewed posts are excluded.
app.get("/api/admin/posts", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT p.id::text AS id,p.user_id,p.content,p.media_url,p.media_type,
              p.media_public_id,p.moderation_status,p.created_at,
              u.username,pr.display_name,
              (SELECT COUNT(*)::int FROM ft_post_reactions l WHERE l.post_id=p.id) AS like_count,
              (SELECT COUNT(*)::int FROM ft_comments c WHERE c.post_id=p.id) AS comment_count
       FROM ft_posts p LEFT JOIN users u ON u.id::text=p.user_id
       LEFT JOIN ft_profiles pr ON pr.user_id=p.user_id
       WHERE p.moderation_status='pending' AND LOWER(COALESCE(p.media_type,''))='video'
       ORDER BY p.created_at ASC LIMIT 200`
    );
    res.json({ posts: result.rows });
  } catch (e) {
    next(e);
  }
});

// ADMIN: review reported posts
app.get("/api/admin/reports", requireAuth, requireModeratorPermission("reports"), async (req, res, next) => {
  try {
    const status = cleanText(req.query.status || "pending", 20);
    if (!["pending", "reviewed", "dismissed", "all"].includes(status)) {
      return res.status(400).json({ error: "Invalid report status." });
    }

    const result = await pool.query(
      `SELECT r.id AS report_id,r.post_id,r.reporter_id,r.reason,r.status,
              r.created_at AS reported_at,p.user_id AS post_owner_id,
              p.content,p.media_url,p.media_type,p.media_public_id,
              reporter.username AS reporter_username,
              author.username AS author_username
       FROM ft_post_reports r JOIN ft_posts p ON p.id=r.post_id
       LEFT JOIN users reporter ON reporter.id::text=r.reporter_id
       LEFT JOIN users author ON author.id::text=p.user_id
       WHERE ($1='all' OR r.status=$1)
       ORDER BY CASE WHEN r.status='pending' THEN 0 ELSE 1 END,
                r.created_at DESC LIMIT 200`,
      [status]
    );

    res.json({ reports: result.rows });
  } catch (e) {
    next(e);
  }
});

app.patch("/api/admin/reports/:id", requireAuth, requireModeratorPermission("reports"), async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const action = cleanText(req.body.action, 30).toLowerCase();
    if (!Number.isSafeInteger(id) || id <= 0 || !["approve", "dismiss", "delete_post"].includes(action)) {
      return res.status(400).json({ error: "Action must be approve, dismiss or delete_post." });
    }

    if (action === "delete_post") {
      const report = await pool.query(
        "SELECT post_id FROM ft_post_reports WHERE id=$1 LIMIT 1", [id]
      );
      if (!report.rowCount) return res.status(404).json({ error: "Report not found." });
      const postId = Number(report.rows[0].post_id);
      const deleted = await deleteSinglePost(postId);
      if (!deleted.found) return res.status(404).json({ error: "Reported post no longer exists." });
      return res.json({
        message: "Reported post and its related database records were deleted.",
        report_id: id, post_id: String(postId), media_deleted: deleted.mediaDeleted,
        warning: deleted.mediaDeleted ? null : "The post was deleted, but its Cloudinary media could not be confirmed deleted."
      });
    }

    const status = action === "approve" ? "reviewed" : "dismissed";
    const result = await pool.query(
      `UPDATE ft_post_reports SET status=$1 WHERE id=$2
       RETURNING id,post_id,status`,
      [status, id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Report not found." });
    res.json({ message: "Report updated.", report: result.rows[0] });
  } catch (e) {
    next(e);
  }
});

// ADDITIVE FEATURES: all original routes above are retained.
function notifyUser(recipientId, actorId, type, message, postId = null) {
  return pool.query(
    `INSERT INTO ft_notifications(recipient_id,actor_id,type,message,post_id)
     VALUES($1,$2,$3,$4,$5)`,
    [String(recipientId),String(actorId),type,message,postId]
  );
}

// Distinct public display name; username remains the login/URL identifier.
app.patch("/api/account/username", requireAuth, async (req,res,next) => {
  try {
    const username = cleanText(req.body.username,50).toLowerCase();
    if (!/^[a-z0-9_]{3,50}$/.test(username)) return res.status(400).json({error:"Username must be 3-50 characters using English letters, numbers or underscores."});
    const r = await pool.query("UPDATE users SET username=$1 WHERE id=$2 RETURNING id::text AS id,username",[username,String(req.user.id)]);
    res.json({message:"Username updated.",user:r.rows[0]});
  } catch(e) { if(e.code === "23505") return res.status(409).json({error:"Username is already taken."}); next(e); }
});

app.get("/api/users/:userId/posts", requireAuth, async (req,res,next) => {
  try {
    const uid=cleanText(req.params.userId,100);
    const r=await pool.query(`SELECT p.id::text AS id,p.user_id,p.content,p.media_url,p.media_type,p.created_at,
      u.username,pr.display_name,pr.avatar_url,
      (SELECT COUNT(*) FROM ft_post_reactions x WHERE x.post_id=p.id) AS reaction_count,
      (SELECT COUNT(*) FROM ft_post_reactions x WHERE x.post_id=p.id) AS like_count,
      (SELECT COUNT(*) FROM ft_comments x WHERE x.post_id=p.id) AS comment_count,
      (SELECT COUNT(*) FROM ft_post_views x WHERE x.post_id=p.id) AS view_count
      FROM ft_posts p JOIN users u ON u.id::text=p.user_id LEFT JOIN ft_profiles pr ON pr.user_id=p.user_id
      WHERE p.user_id=$1 AND u.account_status='active' AND p.moderation_status='approved'
      ORDER BY p.created_at DESC LIMIT 100`,[uid]);
    res.json({posts:r.rows});
  } catch(e){next(e);}
});

// Reactions: love/haha/sad/angry. Legacy /like API remains untouched for old clients.
app.post("/api/posts/:id/reaction", requireAuth, async(req,res,next)=>{
  const id=Number.parseInt(req.params.id,10), reaction=cleanText(req.body.reaction,16).toLowerCase();
  if(!Number.isSafeInteger(id)||id<=0||!['love','haha','sad','angry'].includes(reaction)) return res.status(400).json({error:"Choose love, haha, sad or angry."});
  try{
    const post=await pool.query("SELECT id,user_id FROM ft_posts WHERE id=$1 AND moderation_status='approved'",[id]);
    if(!post.rowCount)return res.status(404).json({error:"Post not found."});
    const old=await pool.query("SELECT reaction FROM ft_post_reactions WHERE post_id=$1 AND user_id=$2",[id,String(req.user.id)]);
    let mine=null;
    if(old.rowCount && old.rows[0].reaction===reaction){await pool.query("DELETE FROM ft_post_reactions WHERE post_id=$1 AND user_id=$2",[id,String(req.user.id)]);}
    else {await pool.query(`INSERT INTO ft_post_reactions(post_id,user_id,reaction) VALUES($1,$2,$3)
      ON CONFLICT(post_id,user_id) DO UPDATE SET reaction=EXCLUDED.reaction,created_at=NOW()`,[id,String(req.user.id),reaction]);mine=reaction;
      if(String(post.rows[0].user_id)!==String(req.user.id)) await notifyUser(post.rows[0].user_id,req.user.id,'reaction',`${req.user.username} reacted ${reaction} to your post.`,id);
    }
    const counts=await pool.query("SELECT reaction,COUNT(*)::int AS count FROM ft_post_reactions WHERE post_id=$1 GROUP BY reaction",[id]);
    res.json({reaction:mine,reaction_counts:Object.fromEntries(counts.rows.map(x=>[x.reaction,x.count])),reaction_count:counts.rows.reduce((n,x)=>n+x.count,0)});
  }catch(e){next(e);}
});

// Messages are retained for 72 hours only. Database rows and message media assets are deleted.
// Cloudinary public IDs are stored separately so assets can be deleted through the authenticated server API.
async function purgeExpiredMessages(){
  if(!pool)return;
  const expired=await pool.query(`SELECT id,media_public_id,media_type FROM ft_messages
    WHERE created_at <= NOW() - INTERVAL '72 hours'`);
  if(cloudinaryConfigured){
    for(const row of expired.rows){
      if(!row.media_public_id)continue;
      try{
        await cloudinary.uploader.destroy(row.media_public_id,{resource_type:row.media_type==='video'?'video':'image',invalidate:true});
      }catch(e){console.error('Expired message media cleanup failed:',e.message);}
    }
  }
  await pool.query("DELETE FROM ft_messages WHERE created_at <= NOW() - INTERVAL '72 hours'");
  // Remove old message-only notifications as well, so they do not leave a stale inbox trace.
  await pool.query("DELETE FROM ft_notifications WHERE type='message' AND created_at <= NOW() - INTERVAL '72 hours'");
}

// Friend request and friend list APIs.
app.post("/api/friends/request", requireAuth, async(req,res,next)=>{
  try{const target=cleanText(req.body.user_id,100),me=String(req.user.id);if(!target||target===me)return res.status(400).json({error:"Choose another user."});
    const u=await pool.query("SELECT id FROM users WHERE id::text=$1 AND account_status='active'",[target]);if(!u.rowCount)return res.status(404).json({error:"User not found."});
    const reciprocal=await pool.query("SELECT id FROM ft_friend_requests WHERE sender_id=$1 AND recipient_id=$2 AND status='pending'",[target,me]);
    if(reciprocal.rowCount){await pool.query("UPDATE ft_friend_requests SET status='accepted',updated_at=NOW() WHERE sender_id=$1 AND recipient_id=$2",[target,me]);await pool.query("INSERT INTO ft_friends(user_id,friend_id) VALUES($1,$2),($2,$1) ON CONFLICT DO NOTHING",[me,target]);await notifyUser(target,me,'friend',`${req.user.username} accepted your friend request.`);return res.json({status:'accepted'});}
    const r=await pool.query(`INSERT INTO ft_friend_requests(sender_id,recipient_id) VALUES($1,$2) ON CONFLICT(sender_id,recipient_id) DO UPDATE SET status='pending',updated_at=NOW() RETURNING id,status`,[me,target]);await notifyUser(target,me,'friend_request',`${req.user.username} sent you a friend request.`);res.status(201).json({request:r.rows[0]});
  }catch(e){next(e);}
});
app.get("/api/friends/requests", requireAuth, async(req,res,next)=>{
  try {
    const me=String(req.user.id);
    const r=await pool.query(`SELECT f.id::text AS id,f.sender_id,f.recipient_id,f.status,
      u.username,p.display_name,p.avatar_url,f.created_at
      FROM ft_friend_requests f JOIN users u ON u.id::text=f.sender_id
      LEFT JOIN ft_profiles p ON p.user_id=f.sender_id
      WHERE f.recipient_id=$1 AND f.status='pending'
      ORDER BY f.created_at DESC`,[me]);
    res.json({requests:r.rows,incoming:r.rows});
  } catch(e){next(e);}
});

app.get("/api/friends/requests/sent", requireAuth, async(req,res,next)=>{
  try {
    const me=String(req.user.id);
    const r=await pool.query(`SELECT f.id::text AS id,f.sender_id,f.recipient_id,f.status,
      u.username,p.display_name,p.avatar_url,f.created_at
      FROM ft_friend_requests f JOIN users u ON u.id::text=f.recipient_id
      LEFT JOIN ft_profiles p ON p.user_id=f.recipient_id
      WHERE f.sender_id=$1 AND f.status='pending'
      ORDER BY f.created_at DESC`,[me]);
    res.json({requests:r.rows,sent:r.rows});
  } catch(e){next(e);}
});

app.delete("/api/friends/requests/:id", requireAuth, async(req,res,next)=>{
  try {
    const id=Number.parseInt(req.params.id,10);
    if(!Number.isSafeInteger(id)) return res.status(400).json({error:"Invalid request ID."});
    const r=await pool.query(`UPDATE ft_friend_requests SET status='cancelled',updated_at=NOW()
      WHERE id=$1 AND sender_id=$2 AND status='pending' RETURNING id`,[id,String(req.user.id)]);
    if(!r.rowCount) return res.status(404).json({error:"Pending sent request not found."});
    res.json({status:"cancelled",message:"Friend request cancelled."});
  } catch(e){next(e);}
});

app.patch("/api/friends/requests/:id", requireAuth, async(req,res,next)=>{try{const id=Number.parseInt(req.params.id,10),action=req.body.action;if(!Number.isSafeInteger(id)||!['accept','decline'].includes(action))return res.status(400).json({error:'Action must be accept or decline.'});const status=action==='accept'?'accepted':'declined';const r=await pool.query(`UPDATE ft_friend_requests SET status=$1,updated_at=NOW() WHERE id=$2 AND recipient_id=$3 AND status='pending' RETURNING sender_id,recipient_id`,[status,id,String(req.user.id)]);if(!r.rowCount)return res.status(404).json({error:'Pending request not found.'});if(action==='accept')await pool.query("INSERT INTO ft_friends(user_id,friend_id) VALUES($1,$2),($2,$1) ON CONFLICT DO NOTHING",[String(req.user.id),r.rows[0].sender_id]);await notifyUser(r.rows[0].sender_id,req.user.id,'friend',action==='accept'?'Your friend request was accepted.':'Your friend request was declined.');res.json({status});}catch(e){next(e);}});
app.get("/api/friends", requireAuth, async(req,res,next)=>{try{const r=await pool.query(`SELECT u.id::text AS id,u.username,p.display_name,p.avatar_url,f.created_at AS friends_since FROM ft_friends f JOIN users u ON u.id::text=f.friend_id LEFT JOIN ft_profiles p ON p.user_id=f.friend_id WHERE f.user_id=$1 AND u.account_status='active' ORDER BY f.created_at DESC`,[String(req.user.id)]);res.json({friends:r.rows});}catch(e){next(e);}});
app.delete("/api/friends/:userId", requireAuth, async(req,res,next)=>{try{const other=cleanText(req.params.userId,100),me=String(req.user.id);await pool.query("DELETE FROM ft_friends WHERE (user_id=$1 AND friend_id=$2) OR (user_id=$2 AND friend_id=$1)",[me,other]);res.json({message:'Friend removed.'});}catch(e){next(e);}});

// Admin notices are broadcast to every active user as in-app notifications.
app.post("/api/admin/notices", requireAuth, requireAdmin, async(req,res,next)=>{try{const title=cleanText(req.body.title,160),body=cleanText(req.body.body,3000);if(!title||!body)return res.status(400).json({error:'Title and notice text are required.'});const n=await pool.query("INSERT INTO ft_admin_notices(admin_id,title,body) VALUES($1,$2,$3) RETURNING *",[String(req.user.id),title,body]);await pool.query(`INSERT INTO ft_notifications(recipient_id,actor_id,type,message) SELECT id::text,$1,'admin_notice',$2 FROM users WHERE account_status='active'`,[String(req.user.id),`${title}: ${body}`]);res.status(201).json({notice:n.rows[0],notified:true});}catch(e){next(e);}});
app.get("/api/admin/notices", requireAuth, requireAdmin, async(req,res,next)=>{try{const r=await pool.query("SELECT * FROM ft_admin_notices ORDER BY created_at DESC LIMIT 100");res.json({notices:r.rows});}catch(e){next(e);}});

// Payment methods are configured by admins. Card payments are intentionally not supported.
app.get('/api/payments/methods', async (req,res,next) => {
  try {
    const r = await pool.query(`SELECT id,code,name,region,currency,price_amount,
             CASE WHEN price_1_month>0 THEN price_1_month ELSE price_amount END AS price_1_month,
             CASE WHEN price_3_months>0 THEN price_3_months ELSE price_amount END AS price_3_months,
             CASE WHEN price_6_months>0 THEN price_6_months ELSE price_amount END AS price_6_months,
             CASE WHEN price_12_months>0 THEN price_12_months ELSE price_amount END AS price_12_months,
             account_name,account_details,instructions,qr_image_url
      FROM ft_payment_methods WHERE enabled=TRUE AND (price_amount>0 OR price_1_month>0 OR price_3_months>0 OR price_6_months>0 OR price_12_months>0) ORDER BY sort_order,name`);
    res.json({methods:r.rows});
  } catch(e) { next(e); }
});

app.get('/api/admin/payment-methods', requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const r = await pool.query('SELECT * FROM ft_payment_methods ORDER BY sort_order,name');
    res.json({methods:r.rows});
  } catch(e) { next(e); }
});

app.post('/api/admin/payment-methods', requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const code=cleanText(req.body.code,50).toLowerCase().replace(/[^a-z0-9_]/g,'_');
    const name=cleanText(req.body.name,80), region=cleanText(req.body.region,20), currency=cleanText(req.body.currency,8).toUpperCase();
    const price=Number(req.body.price_amount), accountName=cleanText(req.body.account_name,160), details=cleanText(req.body.account_details,500), instructions=cleanText(req.body.instructions,1500), qr=cleanText(req.body.qr_image_url,2000), order=Number.parseInt(req.body.sort_order,10)||100;
    if(!code||!name||!['bangladesh','india','global'].includes(region)||!currency||!Number.isFinite(price)||price<0) return res.status(400).json({error:'Valid code, name, region, currency and non-negative price are required.'});
    if(qr && !/^https:\/\//i.test(qr)) return res.status(400).json({error:'QR image URL must use HTTPS.'});
    const enabled=Boolean(req.body.enabled) && (price>0 || Number(req.body.price_1_month)>0 || Number(req.body.price_3_months)>0 || Number(req.body.price_6_months)>0 || Number(req.body.price_12_months)>0) && Boolean(details);
    const r=await pool.query(`INSERT INTO ft_payment_methods(code,name,region,currency,price_amount,price_1_month,price_3_months,price_6_months,price_12_months,account_name,account_details,instructions,qr_image_url,enabled,sort_order,updated_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW()) RETURNING *`,[code,name,region,currency,price,Number(req.body.price_1_month)||0,Number(req.body.price_3_months)||0,Number(req.body.price_6_months)||0,Number(req.body.price_12_months)||0,accountName,details,instructions,qr,enabled,order]);
    res.status(201).json({method:r.rows[0]});
  } catch(e) { if(e.code==='23505') return res.status(409).json({error:'Payment method code already exists.'}); next(e); }
});

app.patch('/api/admin/payment-methods/:id', requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const id=Number.parseInt(req.params.id,10);
    if(!Number.isSafeInteger(id)) return res.status(400).json({error:'Invalid payment method ID.'});
    const current=await pool.query('SELECT * FROM ft_payment_methods WHERE id=$1',[id]);
    if(!current.rowCount) return res.status(404).json({error:'Payment method not found.'});
    const old=current.rows[0], b=req.body;
    const name=b.name===undefined?old.name:cleanText(b.name,80);
    const region=b.region===undefined?old.region:cleanText(b.region,20);
    const currency=b.currency===undefined?old.currency:cleanText(b.currency,8).toUpperCase();
    const price=b.price_amount===undefined?Number(old.price_amount):Number(b.price_amount);
    const price1=b.price_1_month===undefined?Number(old.price_1_month||0):Number(b.price_1_month);
    const price3=b.price_3_months===undefined?Number(old.price_3_months||0):Number(b.price_3_months);
    const price6=b.price_6_months===undefined?Number(old.price_6_months||0):Number(b.price_6_months);
    const price12=b.price_12_months===undefined?Number(old.price_12_months||0):Number(b.price_12_months);
    const accountName=b.account_name===undefined?old.account_name:cleanText(b.account_name,160);
    const details=b.account_details===undefined?old.account_details:cleanText(b.account_details,500);
    const instructions=b.instructions===undefined?old.instructions:cleanText(b.instructions,1500);
    const qr=b.qr_image_url===undefined?old.qr_image_url:cleanText(b.qr_image_url,2000);
    const order=b.sort_order===undefined?old.sort_order:(Number.parseInt(b.sort_order,10)||100);
    const requestedEnabled=b.enabled===undefined?old.enabled:Boolean(b.enabled);
    if(!name||!['bangladesh','india','global'].includes(region)||!currency||![price,price1,price3,price6,price12].every(x=>Number.isFinite(x)&&x>=0)) return res.status(400).json({error:'Invalid payment method details.'});
    if(qr && !/^https:\/\//i.test(qr)) return res.status(400).json({error:'QR image URL must use HTTPS.'});
    const enabled=requestedEnabled && (price>0 || price1>0 || price3>0 || price6>0 || price12>0) && Boolean(details);
    const r=await pool.query(`UPDATE ft_payment_methods SET name=$1,region=$2,currency=$3,price_amount=$4,price_1_month=$5,price_3_months=$6,price_6_months=$7,price_12_months=$8,account_name=$9,account_details=$10,instructions=$11,qr_image_url=$12,enabled=$13,sort_order=$14,updated_at=NOW() WHERE id=$15 RETURNING *`,[name,region,currency,price,price1,price3,price6,price12,accountName,details,instructions,qr,enabled,order,id]);
    res.json({method:r.rows[0]});
  } catch(e) { next(e); }
});

app.delete('/api/admin/payment-methods/:id', requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const id=Number.parseInt(req.params.id,10);
    if(!Number.isSafeInteger(id)) return res.status(400).json({error:'Invalid payment method ID.'});
    const r=await pool.query('UPDATE ft_payment_methods SET enabled=FALSE,updated_at=NOW() WHERE id=$1 RETURNING id,code,enabled',[id]);
    if(!r.rowCount) return res.status(404).json({error:'Payment method not found.'});
    res.json({method:r.rows[0],message:'Payment method disabled.'});
  } catch(e) { next(e); }
});

// Manual submissions are reviewed by an admin before Blue Badge activation.
app.post('/api/payments/manual', requireAuth, async(req,res,next) => {
  try {
    const purpose=cleanText(req.body.purpose,30), amount=Number(req.body.amount), currency=cleanText(req.body.currency||'BDT',8).toUpperCase();
    const method=cleanText(req.body.method,80), ref=cleanText(req.body.transaction_ref,160), payer=cleanText(req.body.payer_account,160);
    const durationMonths=Number.parseInt(req.body.duration_months,10)||1;
    if(!['blue_badge','monetization','other'].includes(purpose)||!Number.isFinite(amount)||amount<=0||!method||!ref) return res.status(400).json({error:'Purpose, valid amount, payment method and transaction reference are required.'});
    if(/card|visa|mastercard|cvv|credit|debit/i.test(method)) return res.status(400).json({error:'Card payments are not supported.'});
    if(purpose==='blue_badge') {
      if(![1,3,6,12].includes(durationMonths)) return res.status(400).json({error:'Choose a badge duration of 1, 3, 6 or 12 months.'});
      const pm=await pool.query(`SELECT name,currency,price_amount,
        CASE WHEN price_1_month>0 THEN price_1_month ELSE price_amount END AS price_1_month,
        CASE WHEN price_3_months>0 THEN price_3_months ELSE price_amount END AS price_3_months,
        CASE WHEN price_6_months>0 THEN price_6_months ELSE price_amount END AS price_6_months,
        CASE WHEN price_12_months>0 THEN price_12_months ELSE price_amount END AS price_12_months
        FROM ft_payment_methods WHERE enabled=TRUE AND account_details<>'' AND LOWER(name)=LOWER($1)`,[method]);
      if(!pm.rowCount) return res.status(400).json({error:'This payment method is not currently available. Please choose an enabled method.'});
      const p=pm.rows[0], priceKey={1:'price_1_month',3:'price_3_months',6:'price_6_months',12:'price_12_months'}[durationMonths];
      if(Number(p[priceKey])!==amount || p.currency!==currency) return res.status(400).json({error:'Payment amount or currency does not match the selected Blue Badge duration price.'});
      const active=await pool.query("SELECT blue_badge_expires_at FROM ft_profiles WHERE user_id=$1 AND blue_badge_status='verified' AND blue_badge_expires_at>NOW()",[String(req.user.id)]);
      const pending=await pool.query("SELECT id FROM ft_manual_payments WHERE user_id=$1 AND purpose='blue_badge' AND status='pending' LIMIT 1",[String(req.user.id)]);
      if(pending.rowCount) return res.status(409).json({error:'You already have a Blue Badge application awaiting review.'});
    }
    const r=await pool.query(`INSERT INTO ft_manual_payments(user_id,purpose,amount,currency,method,transaction_ref,payer_account,duration_months) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id::text AS id,purpose,amount,currency,method,transaction_ref,duration_months,status,created_at`,[String(req.user.id),purpose,amount,currency,method,ref,payer,durationMonths]);
    if(purpose==='blue_badge') await pool.query("INSERT INTO ft_profiles(user_id,display_name,blue_badge_status,blue_badge_duration_months) VALUES($1,$2,'pending',$3) ON CONFLICT(user_id) DO UPDATE SET blue_badge_status=CASE WHEN ft_profiles.blue_badge_expires_at>NOW() THEN 'verified' ELSE 'pending' END,blue_badge_duration_months=EXCLUDED.blue_badge_duration_months,updated_at=NOW()",[String(req.user.id),req.user.username,durationMonths]);
    if(purpose==='monetization') await pool.query("INSERT INTO ft_monetization(user_id,status) VALUES($1,'pending') ON CONFLICT(user_id) DO UPDATE SET status='pending',updated_at=NOW()",[String(req.user.id)]);
    await pool.query(`INSERT INTO ft_notifications(recipient_id,actor_id,type,message) SELECT id::text,$1,'payment',$2 FROM users WHERE LOWER(role)='admin'`,[String(req.user.id),`Manual payment submission (${purpose}) requires review.`]);
    res.status(201).json({payment:r.rows[0],message:'Payment submitted for manual verification.'});
  } catch(e) { if(e.code==='23505') return res.status(409).json({error:'This transaction reference has already been submitted.'}); next(e); }
});
app.get('/api/payments/mine', requireAuth, async(req,res,next)=>{
  try {
    const r=await pool.query(`SELECT id::text AS id,purpose,amount,currency,method,transaction_ref,duration_months,status,admin_note,created_at,reviewed_at FROM ft_manual_payments WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50`,[String(req.user.id)]);
    const b=await pool.query(`SELECT CASE WHEN blue_badge_status='verified' AND blue_badge_expires_at IS NOT NULL AND blue_badge_expires_at<=NOW() THEN 'expired' ELSE blue_badge_status END AS blue_badge_status,blue_badge_duration_months,blue_badge_expires_at,CASE WHEN blue_badge_status='verified' AND blue_badge_expires_at>NOW() THEN TRUE ELSE FALSE END AS blue_badge_active FROM ft_profiles WHERE user_id=$1`,[String(req.user.id)]);
    res.json({payments:r.rows,blue_badge:b.rows[0]||{blue_badge_status:'none',blue_badge_active:false}});
  } catch(e){next(e);}
});
app.get('/api/admin/payments', requireAuth, requireAdmin, async(req,res,next) => {
  try { const status=cleanText(req.query.status||'pending',20); if(!['pending','approved','rejected','all'].includes(status))return res.status(400).json({error:'Invalid payment status filter.'}); const r=await pool.query(`SELECT m.*,u.username,u.email,p.display_name,p.blue_badge_expires_at FROM ft_manual_payments m LEFT JOIN users u ON u.id::text=m.user_id LEFT JOIN ft_profiles p ON p.user_id=m.user_id WHERE ($1='all' OR m.status=$1) ORDER BY m.created_at DESC LIMIT 200`,[status]); res.json({payments:r.rows}); }
  catch(e) { next(e); }
});
app.patch('/api/admin/payments/:id', requireAuth, requireAdmin, async(req,res,next) => {
  const client=await pool.connect();
  try {
    const id=Number.parseInt(req.params.id,10),action=req.body.action,note=cleanText(req.body.admin_note,500);
    if(!Number.isSafeInteger(id)||!['approve','reject'].includes(action)){return res.status(400).json({error:'Action must be approve or reject.'});}
    await client.query('BEGIN');
    const r=await client.query(`UPDATE ft_manual_payments SET status=$1,admin_note=$2,reviewed_at=NOW() WHERE id=$3 AND status='pending' RETURNING *`,[action==='approve'?'approved':'rejected',note,id]);
    if(!r.rowCount){await client.query('ROLLBACK');return res.status(404).json({error:'Pending payment not found.'});}
    const p=r.rows[0];
    if(p.purpose==='blue_badge'){
      if(action==='approve'){
        if(![1,3,6,12].includes(Number(p.duration_months))) throw new Error('Stored Blue Badge duration is invalid.');
        await client.query(`INSERT INTO ft_profiles(user_id,display_name,blue_badge_status,blue_badge_duration_months,blue_badge_expires_at,updated_at)
          VALUES($1,$2,'verified',$3,NOW()+make_interval(months => $3),NOW())
          ON CONFLICT(user_id) DO UPDATE SET blue_badge_status='verified',blue_badge_duration_months=$3,
          blue_badge_expires_at=GREATEST(COALESCE(ft_profiles.blue_badge_expires_at,NOW()),NOW())+make_interval(months => $3),updated_at=NOW()`,[p.user_id,p.user_id,Number(p.duration_months)]);
      } else {
        await client.query(`UPDATE ft_profiles SET blue_badge_status=CASE WHEN blue_badge_expires_at>NOW() THEN 'verified' ELSE 'rejected' END,updated_at=NOW() WHERE user_id=$1`,[p.user_id]);
      }
    }
    if(p.purpose==='monetization') await client.query("INSERT INTO ft_monetization(user_id,enabled,status) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET enabled=EXCLUDED.enabled,status=EXCLUDED.status,updated_at=NOW()",[p.user_id,action==='approve',action==='approve'?'approved':'rejected']);
    await client.query(`INSERT INTO ft_notifications(recipient_id,actor_id,type,message) VALUES($1,$2,'payment',$3)`,[p.user_id,String(req.user.id),p.purpose==='blue_badge'?(action==='approve'?`Your Blue Badge application was approved for ${p.duration_months} month(s).`:'Your Blue Badge application was rejected.'): `Your ${p.purpose} payment was ${action==='approve'?'approved':'rejected'}.`]);
    await client.query('COMMIT');
    const fresh=await pool.query(`SELECT m.*,u.username,u.email,p.blue_badge_expires_at FROM ft_manual_payments m LEFT JOIN users u ON u.id::text=m.user_id LEFT JOIN ft_profiles p ON p.user_id=m.user_id WHERE m.id=$1`,[id]);
    res.json({payment:fresh.rows[0]});
  } catch(e) { await client.query('ROLLBACK').catch(()=>{}); next(e); }
  finally { client.release(); }
});
app.get("/api/monetization/status", requireAuth, async(req,res,next)=>{try{const r=await pool.query("SELECT enabled,status,updated_at FROM ft_monetization WHERE user_id=$1",[String(req.user.id)]);res.json({monetization:r.rows[0]||{enabled:false,status:'not_applied'}});}catch(e){next(e);}});

// Message media uses the same authenticated Cloudinary upload endpoint; send its URL as media_url.
// This endpoint extends existing text messages without removing the old payload contract.
app.post("/api/messages/media", requireAuth, async(req,res,next)=>{try{await purgeExpiredMessages();const recipientId=cleanText(req.body.recipient_id,100),url=cleanText(req.body.media_url,2000),type=cleanText(req.body.media_type,20),publicId=cleanText(req.body.media_public_id,500),content=cleanText(req.body.content,5000);if(!recipientId||recipientId===String(req.user.id)||!url.startsWith('https://res.cloudinary.com/')||!['image','video'].includes(type)||!publicId)return res.status(400).json({error:'Valid recipient, Cloudinary image/video URL and media_public_id are required.'});const recipient=await pool.query("SELECT id FROM users WHERE id::text=$1 AND account_status='active'",[recipientId]);if(!recipient.rowCount)return res.status(404).json({error:'Recipient not found.'});const r=await pool.query("INSERT INTO ft_messages(sender_id,recipient_id,content,media_url,media_type,media_public_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,sender_id,recipient_id,content,media_url,media_type,created_at,read_at",[String(req.user.id),recipientId,content,url,type,publicId]);await notifyUser(recipientId,req.user.id,'message',`New message from ${req.user.username}.`);res.status(201).json({item:r.rows[0],expires_at:new Date(Date.now()+72*60*60*1000).toISOString()});}catch(e){next(e);}});

// Fail-closed moderation helper endpoints. No claim of AI protection until provider/add-on is configured.
app.get("/api/admin/moderation/pending", requireAuth, requireModeratorPermission("moderation"), async(req,res,next)=>{try{const r=await pool.query(`SELECT p.id::text AS id,p.user_id,p.content,p.media_url,p.media_type,p.media_public_id,p.created_at,u.username FROM ft_posts p LEFT JOIN users u ON u.id::text=p.user_id WHERE p.moderation_status='pending' AND LOWER(COALESCE(p.media_type,''))='video' ORDER BY p.created_at ASC LIMIT 200`);res.json({posts:r.rows});}catch(e){next(e);}});
app.patch("/api/admin/moderation/posts/:id", requireAuth, requireModeratorPermission("moderation"), async(req,res,next)=>{
  try {
    const id=Number.parseInt(req.params.id,10), action=cleanText(req.body.action,20).toLowerCase();
    if(!Number.isSafeInteger(id)||!["approve","reject"].includes(action)) return res.status(400).json({error:"Action must be approve or reject."});
    const pending=await pool.query("SELECT id,user_id FROM ft_posts WHERE id=$1 AND moderation_status='pending' AND LOWER(COALESCE(media_type,''))='video'",[id]);
    if(!pending.rowCount) return res.status(404).json({error:"Pending video post not found."});

    if(action === "reject") {
      const deleted=await deleteSinglePost(id);
      if(!deleted.found) return res.status(404).json({error:"Pending video post not found."});
      // Notify the owner after deletion. This notification intentionally has no post_id.
      await pool.query("INSERT INTO ft_notifications(recipient_id,actor_id,type,message) VALUES($1,$2,'moderation',$3)",[String(pending.rows[0].user_id),String(req.user.id),"Your video post was rejected and deleted by an administrator."]);
      return res.json({message:"Video rejected and only that video post was deleted.",post_id:String(id),media_deleted:deleted.mediaDeleted,warning:deleted.mediaDeleted?null:"Post deleted, but Cloudinary media cleanup could not be confirmed."});
    }

    const r=await pool.query("UPDATE ft_posts SET moderation_status='approved',moderation_result=$1::jsonb WHERE id=$2 AND moderation_status='pending' AND LOWER(COALESCE(media_type,''))='video' RETURNING id::text AS id,user_id,moderation_status",[JSON.stringify({reviewed_by:String(req.user.id),reviewed_at:new Date().toISOString(),method:"manual_admin_review"}),id]);
    if(!r.rowCount) return res.status(404).json({error:"Pending video post not found."});
    await notifyUser(r.rows[0].user_id,req.user.id,"moderation","Your video post was approved and is now public.",id);
    res.json({post:r.rows[0]});
  } catch(e) { next(e); }
});


// ============================================================
// BOYS VS GIRLS TOURNAMENT API — PostgreSQL + Social App Auth
// ============================================================

function tournamentDbReady(res) {
  if (!pool) {
    res.status(503).json({ error: "Database is not configured." });
    return false;
  }
  return true;
}

app.get("/api/tournament/tournaments", async (req, res, next) => {
  if (!tournamentDbReady(res)) return;
  try {
    const result = await pool.query(`
      SELECT t.id::text AS id, t.title, t.description, t.tournament_type, t.mode,
             t.registration_open, t.team_limit, t.map_name, t.entry_fee::float8 AS entry_fee,
             t.prize_pool::float8 AS prize_pool, t.prize_mode,
             t.prize_percentage::float8 AS prize_percentage,
             t.max_players, t.banner_url, t.scheduled_at, t.status,
             t.created_at,
             COUNT(r.id) FILTER (WHERE r.status='registered')::int AS registered_count
      FROM ft_tournaments t
      LEFT JOIN ft_tournament_registrations r ON r.tournament_id=t.id
      WHERE t.status <> 'cancelled'
      GROUP BY t.id
      ORDER BY t.scheduled_at ASC NULLS LAST, t.created_at DESC
    `);
    res.json({ tournaments: result.rows });
  } catch (e) { next(e); }
});

app.get("/api/tournament/tournaments/:id", async (req, res, next) => {
  if (!tournamentDbReady(res)) return;
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({ error: "Invalid tournament ID." });
    }
    const result = await pool.query(`
      SELECT t.id::text AS id, t.title, t.description, t.tournament_type, t.mode,
             t.registration_open, t.team_limit, t.map_name, t.entry_fee::float8 AS entry_fee,
             t.prize_pool::float8 AS prize_pool, t.prize_mode,
             t.prize_percentage::float8 AS prize_percentage,
             t.max_players, t.banner_url, t.scheduled_at, t.status,
             t.created_at,
             COUNT(r.id) FILTER (WHERE r.status='registered')::int AS registered_count
      FROM ft_tournaments t
      LEFT JOIN ft_tournament_registrations r ON r.tournament_id=t.id
      WHERE t.id=$1
      GROUP BY t.id
    `, [id]);
    if (!result.rowCount) return res.status(404).json({ error: "Tournament not found." });
    res.json({ tournament: result.rows[0] });
  } catch (e) { next(e); }
});

app.get("/api/tournament/profile", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT tp.free_fire_name, tp.free_fire_uid, tp.updated_at,
             u.username, COALESCE(NULLIF(p.display_name,''),u.username) AS display_name,
             p.avatar_url
      FROM users u
      LEFT JOIN ft_profiles p ON p.user_id=u.id::text
      LEFT JOIN ft_tournament_profiles tp ON tp.user_id=u.id::text
      WHERE u.id::text=$1
      LIMIT 1
    `, [String(req.user.id)]);
    if (!result.rowCount) return res.status(404).json({ error: "Social profile not found." });
    res.json({ profile: result.rows[0] });
  } catch (e) { next(e); }
});

app.put("/api/tournament/profile", requireAuth, async (req, res, next) => {
  try {
    const freeFireName = cleanText(req.body.free_fire_name, 80);
    const freeFireUid = cleanText(req.body.free_fire_uid, 40);
    if (!freeFireName || !/^[0-9]{5,20}$/.test(freeFireUid)) {
      return res.status(400).json({
        error: "Enter your Free Fire name and a valid numeric UID (5–20 digits)."
      });
    }
    const result = await pool.query(`
      INSERT INTO ft_tournament_profiles(user_id,free_fire_name,free_fire_uid,updated_at)
      VALUES($1,$2,$3,NOW())
      ON CONFLICT(user_id) DO UPDATE SET
        free_fire_name=EXCLUDED.free_fire_name,
        free_fire_uid=EXCLUDED.free_fire_uid,
        updated_at=NOW()
      RETURNING free_fire_name,free_fire_uid,updated_at
    `, [String(req.user.id), freeFireName, freeFireUid]);
    res.json({ message: "Tournament profile saved.", profile: result.rows[0] });
  } catch (e) {
    if (e.code === "23505") {
      return res.status(409).json({ error: "This Free Fire UID is already linked to another account." });
    }
    next(e);
  }
});

app.post("/api/tournament/tournaments", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const title = cleanText(req.body.title, 120);
    const description = cleanText(req.body.description, 2000);
    const mode = cleanText(req.body.mode, 20);
    const tournamentType = normalizeTournamentType(req.body.tournament_type || req.body.type || "br-match");
    const mapName = cleanText(req.body.map_name || "Bermuda", 80);
    const entryFee = Number(req.body.entry_fee ?? 0);
    const prizePool = Number(req.body.prize_pool ?? 0);
    const prizeMode = cleanText(req.body.prize_mode || "fixed", 20);
    const prizePercentage = Number(req.body.prize_percentage ?? 0);
    const maxPlayers = Number.parseInt(req.body.max_players, 10);
    const bannerUrl = cleanText(req.body.banner_url, 2000);
    const scheduledAt = req.body.scheduled_at ? new Date(req.body.scheduled_at) : null;

    if (!title || !tournamentType || !["Solo","Duo","Squad"].includes(mode) ||
        !Number.isFinite(entryFee) || entryFee < 0 ||
        !Number.isFinite(prizePool) || prizePool < 0 ||
        !["fixed","dynamic"].includes(prizeMode) ||
        !Number.isFinite(prizePercentage) || prizePercentage < 0 || prizePercentage > 100 ||
        !Number.isSafeInteger(maxPlayers) || maxPlayers < 1 ||
        (scheduledAt && Number.isNaN(scheduledAt.getTime())) ||
        (bannerUrl && !/^https:\/\//i.test(bannerUrl))) {
      return res.status(400).json({ error: "Please provide valid tournament details." });
    }

    const result = await pool.query(`
      INSERT INTO ft_tournaments
        (title,description,tournament_type,mode,map_name,entry_fee,prize_pool,prize_mode,
         prize_percentage,max_players,team_limit,banner_url,scheduled_at,status,created_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'upcoming',$14)
      RETURNING id::text AS id,title,description,tournament_type,mode,map_name,
                entry_fee::float8 AS entry_fee,prize_pool::float8 AS prize_pool,
                prize_mode,prize_percentage::float8 AS prize_percentage,
                max_players,banner_url,scheduled_at,status,created_at
    `, [title,description,tournamentType,mode,mapName,entryFee,prizePool,prizeMode,
        prizePercentage,maxPlayers,tournamentType === "free-fire-cup" ? 13 : maxPlayers,bannerUrl,scheduledAt,String(req.user.id)]);
    res.status(201).json({ message: "Tournament created.", tournament: result.rows[0] });
  } catch (e) { next(e); }
});

app.patch("/api/tournament/tournaments/:id", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Invalid tournament ID." });
    const current = await pool.query("SELECT * FROM ft_tournaments WHERE id=$1", [id]);
    if (!current.rowCount) return res.status(404).json({ error: "Tournament not found." });
    const old = current.rows[0], b = req.body;
    const title = b.title === undefined ? old.title : cleanText(b.title,120);
    const description = b.description === undefined ? old.description : cleanText(b.description,2000);
    const mode = b.mode === undefined ? old.mode : cleanText(b.mode,20);
    const tournamentType = b.tournament_type === undefined && b.type === undefined ? (old.tournament_type || "br-match") : normalizeTournamentType(b.tournament_type || b.type);
    const mapName = b.map_name === undefined ? old.map_name : cleanText(b.map_name,80);
    const entryFee = b.entry_fee === undefined ? Number(old.entry_fee) : Number(b.entry_fee);
    const prizePool = b.prize_pool === undefined ? Number(old.prize_pool) : Number(b.prize_pool);
    const prizeMode = b.prize_mode === undefined ? old.prize_mode : cleanText(b.prize_mode,20);
    const prizePercentage = b.prize_percentage === undefined ? Number(old.prize_percentage) : Number(b.prize_percentage);
    const maxPlayers = b.max_players === undefined ? old.max_players : Number.parseInt(b.max_players,10);
    const bannerUrl = b.banner_url === undefined ? old.banner_url : cleanText(b.banner_url,2000);
    const scheduledAt = b.scheduled_at === undefined ? old.scheduled_at : (b.scheduled_at ? new Date(b.scheduled_at) : null);
    const status = b.status === undefined ? old.status : cleanText(b.status,20);
    if (!title || !tournamentType || !["Solo","Duo","Squad"].includes(mode) ||
        !Number.isFinite(entryFee) || entryFee < 0 ||
        !Number.isFinite(prizePool) || prizePool < 0 ||
        !["fixed","dynamic"].includes(prizeMode) ||
        !Number.isFinite(prizePercentage) || prizePercentage < 0 || prizePercentage > 100 ||
        !Number.isSafeInteger(maxPlayers) || maxPlayers < 1 ||
        !["upcoming","live","completed","cancelled"].includes(status) ||
        (scheduledAt && Number.isNaN(new Date(scheduledAt).getTime())) ||
        (bannerUrl && !/^https:\/\//i.test(bannerUrl))) {
      return res.status(400).json({ error: "Invalid tournament details." });
    }
    const updated = await pool.query(`
      UPDATE ft_tournaments SET title=$1,description=$2,tournament_type=$3,mode=$4,map_name=$5,
        entry_fee=$6,prize_pool=$7,prize_mode=$8,prize_percentage=$9,
        max_players=$10,team_limit=$11,banner_url=$12,scheduled_at=$13,status=$14,updated_at=NOW()
      WHERE id=$15
      RETURNING id::text AS id,title,description,tournament_type,mode,map_name,
        entry_fee::float8 AS entry_fee,prize_pool::float8 AS prize_pool,
        prize_mode,prize_percentage::float8 AS prize_percentage,max_players,
        banner_url,scheduled_at,status,created_at
    `, [title,description,tournamentType,mode,mapName,entryFee,prizePool,prizeMode,
        prizePercentage,maxPlayers,tournamentType === "free-fire-cup" ? 13 : (old.team_limit || maxPlayers),bannerUrl,scheduledAt,status,id]);
    res.json({ tournament: updated.rows[0] });
  } catch (e) { next(e); }
});

app.delete("/api/tournament/tournaments/:id", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id,10);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: "Invalid tournament ID." });
    const result = await pool.query(
      "UPDATE ft_tournaments SET status='cancelled',updated_at=NOW() WHERE id=$1 RETURNING id",
      [id]
    );
    if (!result.rowCount) return res.status(404).json({ error: "Tournament not found." });
    res.json({ message: "Tournament cancelled. Existing records were preserved." });
  } catch (e) { next(e); }
});



// ============================================================
// TOURNAMENT WALLET, MANUAL PAYMENTS & VERIFIED GAME HISTORY
// All money movements are isolated from the Social App wallet.
// ============================================================
app.get("/api/tournament/wallet", requireAuth, async (req, res, next) => {
  try {
    await pool.query(
      "INSERT INTO ft_tournament_wallets(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING",
      [String(req.user.id)]
    );
    const r = await pool.query(
      "SELECT balance::float8 AS balance, updated_at FROM ft_tournament_wallets WHERE user_id=$1",
      [String(req.user.id)]
    );
    res.json({ wallet: r.rows[0] });
  } catch (e) { next(e); }
});

app.get("/api/tournament/transactions", requireAuth, async (req, res, next) => {
  try {
    const r = await pool.query(`
      SELECT id::text AS id,type,amount::float8 AS amount,currency,
             payment_method,transaction_ref,destination,status,admin_note,created_at,updated_at
      FROM ft_tournament_transactions WHERE user_id=$1
      ORDER BY created_at DESC LIMIT 100
    `, [String(req.user.id)]);
    res.json({ transactions: r.rows });
  } catch (e) { next(e); }
});

app.post("/api/tournament/deposits", requireAuth, async (req, res, next) => {
  try {
    const amount = Number(req.body.amount);
    const method = cleanText(req.body.payment_method,80);
    const reference = cleanText(req.body.transaction_ref,160);
    if (!Number.isFinite(amount) || amount < 10 || amount > 10000000 || !method || !reference) {
      return res.status(400).json({ error: "Enter a valid amount, payment method and transaction reference." });
    }
    const configured = await pool.query("SELECT methods FROM ft_tournament_payment_settings WHERE id=1");
    const methods = configured.rows[0]?.methods || [];
    const selected = methods.find(x => String(x.code).toLowerCase() === method.toLowerCase() || String(x.name).toLowerCase() === method.toLowerCase());
    if (!selected || selected.enabled !== true) return res.status(400).json({error:"This Tournament Wallet payment method is not enabled by Admin."});
    const duplicate = await pool.query("SELECT id FROM ft_tournament_transactions WHERE LOWER(payment_method)=LOWER($1) AND transaction_ref=$2 LIMIT 1",[selected.name,reference]);
    if (duplicate.rowCount) return res.status(409).json({error:"This transaction reference has already been submitted."});
    const r = await pool.query(`
      INSERT INTO ft_tournament_transactions
        (user_id,type,amount,payment_method,transaction_ref,status)
      VALUES($1,'deposit',$2,$3,$4,'pending')
      RETURNING id::text AS id,type,amount::float8 AS amount,status,created_at
    `, [String(req.user.id),amount,selected.name,reference]);
    await pool.query(`INSERT INTO ft_notifications(recipient_id,actor_id,type,message) SELECT id::text,$1,'tournament_deposit',$2 FROM users WHERE LOWER(role)='admin'`,[String(req.user.id),`Tournament deposit request from ${req.user.username}.`]);
    res.status(201).json({ message:"Deposit submitted for Admin review.", transaction:r.rows[0] });
  } catch (e) { next(e); }
});

app.post("/api/tournament/withdrawals", requireAuth, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const amount = Number(req.body.amount);
    const method = cleanText(req.body.payment_method,80);
    const destination = cleanText(req.body.destination,180);
    if (!Number.isFinite(amount) || amount < 10 || amount > 10000000 || !method || !destination) {
      return res.status(400).json({ error: "Enter a valid amount, withdrawal method and receiving account." });
    }
    await client.query("BEGIN");
    await client.query("INSERT INTO ft_tournament_wallets(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING",[String(req.user.id)]);
    const w = await client.query("SELECT balance FROM ft_tournament_wallets WHERE user_id=$1 FOR UPDATE",[String(req.user.id)]);
    const pending = await client.query(
      "SELECT COALESCE(SUM(amount),0)::numeric AS amount FROM ft_tournament_transactions WHERE user_id=$1 AND type='withdrawal' AND status='pending'",
      [String(req.user.id)]
    );
    if (Number(w.rows[0].balance) - Number(pending.rows[0].amount) < amount) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error:"Insufficient available Tournament Wallet balance." });
    }
    const configured = await client.query("SELECT methods FROM ft_tournament_payment_settings WHERE id=1");
    const methods = configured.rows[0]?.methods || [];
    const selected = methods.find(x => String(x.code).toLowerCase() === method.toLowerCase() || String(x.name).toLowerCase() === method.toLowerCase());
    if (!selected || selected.enabled !== true) { await client.query("ROLLBACK"); return res.status(400).json({error:"This Tournament Wallet withdrawal method is not enabled by Admin."}); }
    const r = await client.query(`
      INSERT INTO ft_tournament_transactions(user_id,type,amount,payment_method,destination,status)
      VALUES($1,'withdrawal',$2,$3,$4,'pending')
      RETURNING id::text AS id,type,amount::float8 AS amount,status,created_at
    `,[String(req.user.id),amount,selected.name,destination]);
    await client.query(`INSERT INTO ft_notifications(recipient_id,actor_id,type,message) SELECT id::text,$1,'tournament_withdrawal',$2 FROM users WHERE LOWER(role)='admin'`,[String(req.user.id),`Tournament withdrawal request from ${req.user.username}.`]);
    await client.query("COMMIT");
    res.status(201).json({message:"Withdrawal request submitted for Admin review.",transaction:r.rows[0]});
  } catch(e) {
    await client.query("ROLLBACK").catch(()=>{});
    next(e);
  } finally { client.release(); }
});

// Admin payment queue. Approvals are idempotent and balance updates are atomic.
app.get("/api/admin/tournament/transactions", requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const status = cleanText(req.query.status || "pending",20);
    if (!["pending","approved","rejected","completed","all"].includes(status))
      return res.status(400).json({error:"Invalid status filter."});
    const r = await pool.query(`
      SELECT t.id::text AS id,t.user_id,u.username,t.type,t.amount::float8 AS amount,
        t.currency,t.payment_method,t.transaction_ref,t.destination,t.status,t.admin_note,t.created_at
      FROM ft_tournament_transactions t LEFT JOIN users u ON u.id::text=t.user_id
      WHERE ($1='all' OR t.status=$1) ORDER BY t.created_at ASC LIMIT 300
    `,[status]);
    res.json({transactions:r.rows});
  } catch(e) { next(e); }
});

app.patch("/api/admin/tournament/transactions/:id", requireAuth, requireAdmin, async (req,res,next) => {
  const client = await pool.connect();
  try {
    const id = Number.parseInt(req.params.id,10);
    const action = cleanText(req.body.action,20);
    const note = cleanText(req.body.admin_note,500);
    if (!Number.isSafeInteger(id) || id < 1 || !["approve","reject"].includes(action))
      return res.status(400).json({error:"Invalid transaction review request."});
    await client.query("BEGIN");
    const q = await client.query("SELECT * FROM ft_tournament_transactions WHERE id=$1 FOR UPDATE",[id]);
    if (!q.rowCount) { await client.query("ROLLBACK"); return res.status(404).json({error:"Transaction not found."}); }
    const tx = q.rows[0];
    if (tx.status !== "pending") { await client.query("ROLLBACK"); return res.status(409).json({error:"This request has already been reviewed."}); }
    await client.query("INSERT INTO ft_tournament_wallets(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING",[tx.user_id]);
    if (action === "approve" && tx.type === "deposit") {
      await client.query("UPDATE ft_tournament_wallets SET balance=balance+$2,updated_at=NOW() WHERE user_id=$1",[tx.user_id,tx.amount]);
    }
    if (action === "approve" && tx.type === "withdrawal") {
      const w = await client.query("SELECT balance FROM ft_tournament_wallets WHERE user_id=$1 FOR UPDATE",[tx.user_id]);
      const pendingOthers = await client.query(
        "SELECT COALESCE(SUM(amount),0)::numeric AS amount FROM ft_tournament_transactions WHERE user_id=$1 AND type='withdrawal' AND status='pending' AND id<>$2",
        [tx.user_id,id]
      );
      if (Number(w.rows[0].balance) - Number(pendingOthers.rows[0].amount) < Number(tx.amount)) {
        await client.query("ROLLBACK");
        return res.status(409).json({error:"Wallet balance is no longer sufficient; request was not approved."});
      }
      await client.query("UPDATE ft_tournament_wallets SET balance=balance-$2,updated_at=NOW() WHERE user_id=$1",[tx.user_id,tx.amount]);
    }
    const status = action === "reject" ? "rejected" : (tx.type === "withdrawal" ? "completed" : "approved");
    const updated = await client.query(`
      UPDATE ft_tournament_transactions SET status=$1,admin_note=$2,reviewed_by=$3,
        reviewed_at=NOW(),updated_at=NOW() WHERE id=$4
      RETURNING id::text AS id,type,amount::float8 AS amount,status,admin_note,reviewed_at
    `,[status,note,String(req.user.id),id]);
    await client.query(`INSERT INTO ft_notifications(recipient_id,actor_id,type,message) VALUES($1,$2,'tournament_transaction',$3)`,[tx.user_id,String(req.user.id),`Your Tournament Wallet ${tx.type} request was ${status}. ${note}`]);
    await client.query("COMMIT");
    res.json({message:`Transaction ${status}.`,transaction:updated.rows[0]});
  } catch(e) {
    await client.query("ROLLBACK").catch(()=>{});
    next(e);
  } finally { client.release(); }
});

app.get("/api/tournament/game-history", requireAuth, async (req,res,next) => {
  try {
    const r = await pool.query(`
      SELECT h.id::text AS id,h.match_name,h.game_mode,h.played_at,h.player_or_team,
        h.rank,h.kills,h.result,h.prize_amount::float8 AS prize_amount,h.status
      FROM ft_tournament_game_history h
      WHERE h.user_id=$1 AND h.status='verified'
      ORDER BY h.played_at DESC NULLS LAST,h.created_at DESC LIMIT 100
    `,[String(req.user.id)]);
    res.json({history:r.rows});
  } catch(e) { next(e); }
});

app.get("/api/admin/tournament/game-history", requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const status=cleanText(req.query.status || "pending",20);
    if (!["pending","verified","rejected","all"].includes(status))
      return res.status(400).json({error:"Invalid status filter."});
    const r=await pool.query(`
      SELECT h.id::text AS id,h.user_id,u.username,h.match_name,h.game_mode,h.played_at,
        h.player_or_team,h.rank,h.kills,h.result,h.prize_amount::float8 AS prize_amount,h.status
      FROM ft_tournament_game_history h LEFT JOIN users u ON u.id::text=h.user_id
      WHERE ($1='all' OR h.status=$1) ORDER BY h.created_at DESC LIMIT 300
    `,[status]);
    res.json({history:r.rows});
  } catch(e) { next(e); }
});

app.post("/api/admin/tournament/game-history", requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const userId=cleanText(req.body.user_id,100);
    const matchName=cleanText(req.body.match_name,140);
    const gameMode=cleanText(req.body.game_mode,40);
    const playerOrTeam=cleanText(req.body.player_or_team,120);
    const result=cleanText(req.body.result,120);
    const rank=req.body.rank===null || req.body.rank==="" || req.body.rank===undefined ? null : Number(req.body.rank);
    const kills=Number(req.body.kills ?? 0);
    const prize=Number(req.body.prize_amount ?? 0);
    const playedAt=req.body.played_at ? new Date(req.body.played_at) : new Date();
    if (!userId || !matchName || !playerOrTeam || (rank!==null && (!Number.isInteger(rank)||rank<1)) ||
        !Number.isInteger(kills)||kills<0||!Number.isFinite(prize)||prize<0||Number.isNaN(playedAt.getTime()))
      return res.status(400).json({error:"Invalid game history details."});
    const r=await pool.query(`
      INSERT INTO ft_tournament_game_history
        (user_id,tournament_id,match_name,game_mode,played_at,player_or_team,rank,kills,result,prize_amount,status,verified_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'verified',$11)
      RETURNING id::text AS id,user_id,match_name,game_mode,played_at,player_or_team,rank,kills,result,prize_amount::float8 AS prize_amount,status
    `,[userId,req.body.tournament_id ? Number(req.body.tournament_id) : null,matchName,gameMode,playedAt,playerOrTeam,rank,kills,result,prize,String(req.user.id)]);
    if (prize > 0) {
      await pool.query("INSERT INTO ft_tournament_wallets(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING",[userId]);
      await pool.query("UPDATE ft_tournament_wallets SET balance=balance+$2,updated_at=NOW() WHERE user_id=$1",[userId,prize]);
      await pool.query(`INSERT INTO ft_tournament_transactions(user_id,type,amount,status,admin_note,reviewed_by,reviewed_at)
        VALUES($1,'prize',$2,'completed','Tournament prize credited',$3,NOW())`,[userId,prize,String(req.user.id)]);
    }
    res.status(201).json({history:r.rows[0]});
  } catch(e) { next(e); }
});



// ============================================================
// TOURNAMENT ADMIN <-> USER CONNECTION FIX (additive routes)
// ============================================================
const TOURNAMENT_TYPES = ["br-match", "clash-squad", "free-fire-cup"];
const TOURNAMENT_METHODS = ["bkash", "nagad", "rocket", "binance", "redotpay"];
const CUP_ROUND_COUNTS = [13, 10, 8, 4, 2, 1];

function normalizeTournamentType(value) {
  const v = cleanText(value, 30).toLowerCase().replace(/_/g, "-");
  return TOURNAMENT_TYPES.includes(v) ? v : "";
}
function teamPlayerCount(mode, type) {
  return type === "free-fire-cup" || mode === "Squad" ? 4 : mode === "Duo" ? 2 : 1;
}
function validatePlayers(players, expected) {
  if (!Array.isArray(players) || players.length !== expected) return "Exactly " + expected + " player(s) are required.";
  const seen = new Set();
  for (const p of players) {
    const name = cleanText(p?.name || p?.free_fire_name, 80);
    const uid = cleanText(p?.uid || p?.free_fire_uid, 20);
    if (!name || !/^[0-9]{5,20}$/.test(uid)) return "Every player needs a Free Fire name and numeric UID (5–20 digits).";
    if (seen.has(uid)) return "A player UID cannot be repeated in the same team.";
    seen.add(uid);
  }
  return "";
}

// Public payment methods are read-only to users; credentials/secrets are never stored here.
app.get("/api/tournament/payment-settings", async (req,res,next) => {
  try {
    const r = await pool.query("SELECT methods,updated_at FROM ft_tournament_payment_settings WHERE id=1");
    res.json({ methods: r.rows[0]?.methods || [], updated_at: r.rows[0]?.updated_at || null });
  } catch(e) { next(e); }
});
app.get("/api/admin/tournament/payment-settings", requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const r = await pool.query("SELECT methods,updated_at FROM ft_tournament_payment_settings WHERE id=1");
    res.json({ methods: r.rows[0]?.methods || [], updated_at: r.rows[0]?.updated_at || null });
  } catch(e) { next(e); }
});
app.put("/api/admin/tournament/payment-settings", requireAuth, requireAdmin, async (req,res,next) => {
  try {
    if (!Array.isArray(req.body.methods)) return res.status(400).json({error:"methods must be an array."});
    const supplied = new Map();
    for (const item of req.body.methods) {
      const code = cleanText(item?.code,30).toLowerCase();
      if (!TOURNAMENT_METHODS.includes(code) || supplied.has(code)) return res.status(400).json({error:"Only bKash, Nagad, Rocket, Binance and RedotPay can be configured."});
      const account = cleanText(item.account || item.account_details,180);
      const instructions = cleanText(item.instructions,500);
      supplied.set(code,{code,name:({bkash:"bKash",nagad:"Nagad",rocket:"Rocket",binance:"Binance",redotpay:"RedotPay"})[code],enabled:Boolean(item.enabled) && Boolean(account),account,instructions});
    }
    const methods = TOURNAMENT_METHODS.map(code => supplied.get(code) || ({code,name:({bkash:"bKash",nagad:"Nagad",rocket:"Rocket",binance:"Binance",redotpay:"RedotPay"})[code],enabled:false,account:"",instructions:""}));
    const r = await pool.query(`INSERT INTO ft_tournament_payment_settings(id,methods,updated_by,updated_at) VALUES(1,$1::jsonb,$2,NOW()) ON CONFLICT(id) DO UPDATE SET methods=EXCLUDED.methods,updated_by=EXCLUDED.updated_by,updated_at=NOW() RETURNING methods,updated_at`,[JSON.stringify(methods),String(req.user.id)]);
    res.json({message:"Tournament payment settings saved.",methods:r.rows[0].methods,updated_at:r.rows[0].updated_at});
  } catch(e) { next(e); }
});

// Admin tournament list alias used by the Admin dashboard.
app.get("/api/admin/tournament/tournaments", requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const r = await pool.query(`SELECT t.id::text AS id,t.title,t.description,t.tournament_type,t.mode,t.map_name,t.entry_fee::float8 AS entry_fee,t.prize_pool::float8 AS prize_pool,t.prize_mode,t.prize_percentage::float8 AS prize_percentage,t.max_players,t.team_limit,t.registration_open,t.banner_url,t.scheduled_at,t.status,COUNT(DISTINCT tm.id) FILTER(WHERE tm.status='approved')::int AS approved_teams,COUNT(DISTINCT tm.id)::int AS total_teams FROM ft_tournaments t LEFT JOIN ft_tournament_teams tm ON tm.tournament_id=t.id GROUP BY t.id ORDER BY t.created_at DESC`);
    res.json({tournaments:r.rows});
  } catch(e) { next(e); }
});

// Add/replace tournament type support while retaining old tournament fields and records.
app.post("/api/tournament/teams/register", requireAuth, async (req,res,next) => {
  const client = await pool.connect();
  try {
    const tournamentId = Number.parseInt(req.body.tournament_id,10);
    const teamName = cleanText(req.body.team_name,100) || req.user.username;
    if (!Number.isSafeInteger(tournamentId) || tournamentId < 1) {
      return res.status(400).json({error:"Valid tournament_id is required."});
    }

    await client.query("BEGIN");
    // Lock the tournament row so simultaneous joins cannot overbook the last slot.
    const t = await client.query(
      `SELECT id,tournament_type,mode,team_limit,max_players,registration_open,status,entry_fee,title,scheduled_at
       FROM ft_tournaments WHERE id=$1 FOR UPDATE`,
      [tournamentId]
    );
    if (!t.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({error:"Tournament not found."});
    }
    const tournament = t.rows[0];
    if (tournament.registration_open === false || tournament.status !== "upcoming") {
      await client.query("ROLLBACK");
      return res.status(409).json({error:"Registration is closed."});
    }
    if (tournament.scheduled_at && new Date(tournament.scheduled_at).getTime() <= Date.now()) {
      await client.query("ROLLBACK");
      return res.status(409).json({error:"Tournament registration has closed because the start time has passed."});
    }

    const type = normalizeTournamentType(tournament.tournament_type) || "br-match";
    const expected = teamPlayerCount(tournament.mode,type);
    const players = req.body.players;
    const problem = validatePlayers(players,expected);
    if (problem) {
      await client.query("ROLLBACK");
      return res.status(400).json({error:problem});
    }

    // Captain must use the Free Fire identity saved in their authenticated profile.
    const profile = await client.query(
      "SELECT free_fire_name,free_fire_uid FROM ft_tournament_profiles WHERE user_id=$1",
      [String(req.user.id)]
    );
    if (!profile.rowCount || !profile.rows[0].free_fire_name || !profile.rows[0].free_fire_uid) {
      await client.query("ROLLBACK");
      return res.status(400).json({error:"Save your Free Fire Name and UID in your Tournament Profile before joining."});
    }
    const captainName = cleanText(profile.rows[0].free_fire_name,80);
    const captainUid = cleanText(profile.rows[0].free_fire_uid,20);
    const submittedCaptain = players[0] || {};
    if (cleanText(submittedCaptain.name || submittedCaptain.free_fire_name,80) !== captainName ||
        cleanText(submittedCaptain.uid || submittedCaptain.free_fire_uid,20) !== captainUid) {
      await client.query("ROLLBACK");
      return res.status(400).json({error:"The first player must be your saved Free Fire profile."});
    }

    const normalized = players.map(p=>({
      name:cleanText(p.name || p.free_fire_name,80),
      uid:cleanText(p.uid || p.free_fire_uid,20)
    }));

    const existing = await client.query(
      "SELECT id FROM ft_tournament_teams WHERE tournament_id=$1 AND captain_user_id=$2 LIMIT 1",
      [tournamentId,String(req.user.id)]
    );
    if (existing.rowCount) {
      await client.query("ROLLBACK");
      return res.status(409).json({error:"You have already joined this tournament."});
    }

    const count = await client.query(
      "SELECT COUNT(*)::int AS n FROM ft_tournament_teams WHERE tournament_id=$1 AND status IN ('approved','pending')",
      [tournamentId]
    );
    const maxTeams = type === "free-fire-cup"
      ? 13
      : (Number(tournament.team_limit) > 0
          ? Number(tournament.team_limit)
          : Math.max(1,Math.floor(Number(tournament.max_players || expected) / expected)));
    if (Number(count.rows[0].n) >= maxTeams) {
      await client.query("ROLLBACK");
      return res.status(409).json({error:"All tournament slots are full."});
    }

    const fee = Number(tournament.entry_fee || 0);
    if (!Number.isFinite(fee) || fee < 0) {
      await client.query("ROLLBACK");
      return res.status(409).json({error:"Tournament entry fee is invalid. Please contact Admin."});
    }

    // For Solo, Duo and Squad the captain is the payer. Teammates do not need wallets.
    await client.query(
      "INSERT INTO ft_tournament_wallets(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING",
      [String(req.user.id)]
    );
    const wallet = await client.query(
      "SELECT balance FROM ft_tournament_wallets WHERE user_id=$1 FOR UPDATE",
      [String(req.user.id)]
    );
    if (Number(wallet.rows[0].balance) < fee) {
      await client.query("ROLLBACK");
      return res.status(400).json({error:`Insufficient Tournament Wallet balance. Required: ৳${fee.toLocaleString("en-BD")}.`});
    }

    if (fee > 0) {
      await client.query(
        "UPDATE ft_tournament_wallets SET balance=balance-$2,updated_at=NOW() WHERE user_id=$1",
        [String(req.user.id),fee]
      );
    }

    const team = await client.query(
      `INSERT INTO ft_tournament_teams(tournament_id,captain_user_id,team_name,players,status,admin_note,updated_at)
       VALUES($1,$2,$3,$4::jsonb,'approved','',NOW())
       RETURNING id::text AS id,tournament_id::text AS tournament_id,team_name,players,status,created_at`,
      [tournamentId,String(req.user.id),teamName,JSON.stringify(normalized)]
    );

    await client.query(
      `INSERT INTO ft_tournament_registrations(tournament_id,user_id,status)
       VALUES($1,$2,'registered')
       ON CONFLICT(tournament_id,user_id) DO UPDATE SET status='registered'`,
      [tournamentId,String(req.user.id)]
    );

    if (fee > 0) {
      await client.query(
        `INSERT INTO ft_tournament_transactions(user_id,type,amount,status,admin_note,reviewed_at,updated_at)
         VALUES($1,'entry_fee',$2,'completed',$3,NOW(),NOW())`,
        [String(req.user.id),fee,`Entry fee for ${tournament.title} (Team #${team.rows[0].id})`]
      );
    }

    await client.query("COMMIT");
    res.status(201).json({
      message:"Tournament joined successfully. No Admin approval is required.",
      team:team.rows[0],
      charged_amount:fee,
      payer_user_id:String(req.user.id)
    });
  } catch(e) {
    await client.query("ROLLBACK").catch(()=>{});
    if (e.code === "23505") return res.status(409).json({error:"You have already joined this tournament."});
    next(e);
  } finally {
    client.release();
  }
});

app.get("/api/tournament/my-teams", requireAuth, async (req,res,next) => {
  try { const r=await pool.query(`SELECT tm.id::text AS id,tm.tournament_id::text AS tournament_id,tm.team_name,tm.players,tm.status,tm.admin_note,tm.created_at,t.title,t.tournament_type,t.mode FROM ft_tournament_teams tm JOIN ft_tournaments t ON t.id=tm.tournament_id WHERE tm.captain_user_id=$1 ORDER BY tm.created_at DESC`,[String(req.user.id)]); res.json({teams:r.rows}); }
  catch(e){next(e);}
});
app.get("/api/admin/tournament/teams", requireAuth, requireAdmin, async (req,res,next) => {
  try { const status=cleanText(req.query.status||"all",20); if(!["all","pending","approved","rejected","disqualified"].includes(status)) return res.status(400).json({error:"Invalid team status."}); const r=await pool.query(`SELECT tm.id::text AS id,tm.tournament_id::text AS tournament_id,tm.captain_user_id,u.username,tm.team_name,tm.players,tm.status,tm.admin_note,tm.created_at,t.title,t.tournament_type,t.mode FROM ft_tournament_teams tm JOIN ft_tournaments t ON t.id=tm.tournament_id LEFT JOIN users u ON u.id::text=tm.captain_user_id WHERE ($1='all' OR tm.status=$1) ORDER BY tm.created_at DESC LIMIT 500`,[status]); res.json({teams:r.rows}); }
  catch(e){next(e);}
});
app.get("/api/admin/tournament/tournaments/:id/teams", requireAuth, requireAdmin, async (req,res,next) => {
  try { const id=Number.parseInt(req.params.id,10); if(!Number.isSafeInteger(id)||id<1)return res.status(400).json({error:"Invalid tournament ID."}); const r=await pool.query(`SELECT tm.id::text AS id,tm.tournament_id::text AS tournament_id,tm.captain_user_id,u.username,tm.team_name,tm.players,tm.status,tm.admin_note,tm.created_at FROM ft_tournament_teams tm LEFT JOIN users u ON u.id::text=tm.captain_user_id WHERE tm.tournament_id=$1 ORDER BY tm.created_at`,[id]); res.json({teams:r.rows}); }
  catch(e){next(e);}
});
app.patch("/api/admin/tournament/teams/:teamId", requireAuth, requireAdmin, async (req,res,next) => {
  try { const id=Number.parseInt(req.params.teamId,10),status=cleanText(req.body.status||req.body.action,20).toLowerCase(),note=cleanText(req.body.admin_note,500); const nextStatus=({approve:"approved",reject:"rejected",disqualify:"disqualified",approved:"approved",rejected:"rejected",disqualified:"disqualified"})[status]; if(!Number.isSafeInteger(id)||id<1||!nextStatus)return res.status(400).json({error:"Choose approve, reject or disqualify."}); const r=await pool.query(`UPDATE ft_tournament_teams SET status=$1,admin_note=$2,updated_at=NOW() WHERE id=$3 RETURNING id::text AS id,tournament_id::text AS tournament_id,captain_user_id,team_name,players,status,admin_note`,[nextStatus,note,id]); if(!r.rowCount)return res.status(404).json({error:"Team registration not found."}); await pool.query(`INSERT INTO ft_notifications(recipient_id,actor_id,type,message) VALUES($1,$2,'tournament', $3)`,[r.rows[0].captain_user_id,String(req.user.id),`Your team ${r.rows[0].team_name} registration was ${nextStatus}. ${note}`]); res.json({team:r.rows[0]}); }
  catch(e){next(e);}
});

// Knockout setup and scoring. Free Fire Cup uses 13 -> 10 -> 8 -> 4 -> 2 -> 1.
app.get("/api/admin/tournament/tournaments/:id/knockout", requireAuth, requireAdmin, async (req,res,next) => {
  try { const id=Number.parseInt(req.params.id,10); if(!Number.isSafeInteger(id)||id<1)return res.status(400).json({error:"Invalid tournament ID."}); const r=await pool.query(`SELECT k.id::text AS id,k.round_number,k.round_name,k.team_id::text AS team_id,k.position,k.score,k.qualified,tm.team_name,tm.players FROM ft_tournament_knockout k JOIN ft_tournament_teams tm ON tm.id=k.team_id WHERE k.tournament_id=$1 ORDER BY k.round_number,k.position`,[id]); res.json({rounds:r.rows,expected_counts:CUP_ROUND_COUNTS}); }
  catch(e){next(e);}
});
app.post("/api/admin/tournament/tournaments/:id/knockout", requireAuth, requireAdmin, async (req,res,next) => {
  const client=await pool.connect();
  try { const id=Number.parseInt(req.params.id,10),round=Number.parseInt(req.body.round_number,10); if(!Number.isSafeInteger(id)||id<1||!Number.isSafeInteger(round)||round<1||round>6)return res.status(400).json({error:"Invalid tournament or round."}); const t=await client.query("SELECT tournament_type FROM ft_tournaments WHERE id=$1",[id]); if(!t.rowCount)return res.status(404).json({error:"Tournament not found."}); const isCup=normalizeTournamentType(t.rows[0].tournament_type)==="free-fire-cup"; const teams=Array.isArray(req.body.teams)?req.body.teams:[]; if(!teams.length)return res.status(400).json({error:"Select teams for this round."}); const expected=isCup?CUP_ROUND_COUNTS[round-1]:teams.length; if(isCup&&teams.length!==expected)return res.status(400).json({error:`Round ${round} must contain ${expected} teams.`}); const ids=teams.map(x=>Number.parseInt(typeof x==="object"?x.team_id:x,10)); if(ids.some(x=>!Number.isSafeInteger(x)||x<1)||new Set(ids).size!==ids.length)return res.status(400).json({error:"Team IDs must be unique valid IDs."}); await client.query("BEGIN"); const valid=await client.query("SELECT id FROM ft_tournament_teams WHERE tournament_id=$1 AND id=ANY($2::bigint[]) AND status='approved'",[id,ids]); if(valid.rowCount!==ids.length){await client.query("ROLLBACK");return res.status(400).json({error:"Every selected team must be approved and belong to this tournament."});} for(let i=0;i<ids.length;i++){const x=typeof teams[i]==="object"?teams[i]:{}; await client.query(`INSERT INTO ft_tournament_knockout(tournament_id,round_number,round_name,team_id,position,score,qualified) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tournament_id,round_number,team_id) DO UPDATE SET round_name=EXCLUDED.round_name,position=EXCLUDED.position,score=EXCLUDED.score,qualified=EXCLUDED.qualified,updated_at=NOW()`,[id,round,`Round ${round}`,ids[i],Number.parseInt(x.position,10)||i+1,Number(x.score)||0,Boolean(x.qualified)]);} await client.query("COMMIT"); const out=await pool.query("SELECT id::text AS id,round_number,round_name,team_id::text AS team_id,position,score::float8 AS score,qualified FROM ft_tournament_knockout WHERE tournament_id=$1 AND round_number=$2 ORDER BY position",[id,round]); res.json({message:"Knockout round saved.",rounds:out.rows}); }
  catch(e){await client.query("ROLLBACK").catch(()=>{});next(e);} finally{client.release();}
});

// Compatibility aliases for the earlier Tournament Admin HTML route names.
app.get("/api/tournament/admin/tournaments/:id/teams", requireAuth, requireAdmin, async (req,res,next) => {
  try { const id=Number.parseInt(req.params.id,10); if(!Number.isSafeInteger(id)||id<1)return res.status(400).json({error:"Invalid tournament ID."}); const r=await pool.query(`SELECT tm.id::text AS id,tm.tournament_id::text AS tournament_id,tm.captain_user_id,u.username,tm.team_name,tm.players,tm.status,tm.admin_note,tm.created_at FROM ft_tournament_teams tm LEFT JOIN users u ON u.id::text=tm.captain_user_id WHERE tm.tournament_id=$1 ORDER BY tm.created_at DESC`,[id]); res.json({teams:r.rows}); } catch(e){next(e);}
});
app.post("/api/tournament/admin/tournaments/:id/teams", requireAuth, requireAdmin, async (req,res,next) => {
  try { const id=Number.parseInt(req.params.id,10); const userId=cleanText(req.body.user_id,100); const teamName=cleanText(req.body.team_name,100); const players=req.body.players; if(!Number.isSafeInteger(id)||id<1||!userId||!teamName||!Array.isArray(players))return res.status(400).json({error:"Tournament, captain user, team name and players are required."}); const t=await pool.query("SELECT tournament_type,mode FROM ft_tournaments WHERE id=$1",[id]); if(!t.rowCount)return res.status(404).json({error:"Tournament not found."}); const expected=teamPlayerCount(t.rows[0].mode,normalizeTournamentType(t.rows[0].tournament_type)); const problem=validatePlayers(players,expected); if(problem)return res.status(400).json({error:problem}); const u=await pool.query("SELECT id FROM users WHERE id::text=$1 AND account_status='active'",[userId]); if(!u.rowCount)return res.status(404).json({error:"Captain user not found."}); const normalized=players.map(p=>({name:cleanText(p.name||p.free_fire_name,80),uid:cleanText(p.uid||p.free_fire_uid,20)})); const r=await pool.query(`INSERT INTO ft_tournament_teams(tournament_id,captain_user_id,team_name,players,status) VALUES($1,$2,$3,$4::jsonb,'approved') RETURNING id::text AS id,tournament_id::text AS tournament_id,team_name,players,status,created_at`,[id,userId,teamName,JSON.stringify(normalized)]); await pool.query(`INSERT INTO ft_tournament_registrations(tournament_id,user_id,status) VALUES($1,$2,'registered') ON CONFLICT(tournament_id,user_id) DO UPDATE SET status='registered'`,[id,userId]); res.status(201).json({team:r.rows[0]}); } catch(e){if(e.code==='23505')return res.status(409).json({error:"Team already exists for this user."});next(e);}
});
app.get("/api/tournament/admin/tournaments/:id/knockout", requireAuth, requireAdmin, async (req,res,next) => {
  try { const id=Number.parseInt(req.params.id,10); if(!Number.isSafeInteger(id)||id<1)return res.status(400).json({error:"Invalid tournament ID."}); const r=await pool.query(`SELECT k.id::text AS id,k.round_number,k.round_name,k.team_id::text AS team_id,k.position,k.score::float8 AS score,k.qualified,tm.team_name,tm.players FROM ft_tournament_knockout k JOIN ft_tournament_teams tm ON tm.id=k.team_id WHERE k.tournament_id=$1 ORDER BY k.round_number,k.position`,[id]); res.json({rounds:r.rows,expected_counts:CUP_ROUND_COUNTS}); } catch(e){next(e);}
});
app.post("/api/tournament/admin/tournaments/:id/knockout", requireAuth, requireAdmin, (req,res,next) => { req.url = `/api/admin/tournament/tournaments/${req.params.id}/knockout`; next(); });
app.post("/api/tournament/tournaments/:id/register", requireAuth, (req,res,next) => { req.body.tournament_id=req.params.id; req.url="/api/tournament/teams/register"; next(); });
app.patch("/api/admin/tournament/tournaments/:id/teams/:teamId", requireAuth, requireAdmin, async (req,res,next) => {
  try { const id=Number.parseInt(req.params.teamId,10),status=cleanText(req.body.status||req.body.action,20).toLowerCase(),note=cleanText(req.body.admin_note,500); const mapped=({approve:"approved",reject:"rejected",disqualify:"disqualified",approved:"approved",rejected:"rejected",disqualified:"disqualified"})[status]; if(!Number.isSafeInteger(id)||id<1||!mapped)return res.status(400).json({error:"Invalid team review."}); const r=await pool.query(`UPDATE ft_tournament_teams SET status=$1,admin_note=$2,updated_at=NOW() WHERE id=$3 AND tournament_id=$4 RETURNING id::text AS id,captain_user_id,team_name,players,status,admin_note`,[mapped,note,id,Number.parseInt(req.params.id,10)]); if(!r.rowCount)return res.status(404).json({error:"Team not found."}); await pool.query(`INSERT INTO ft_notifications(recipient_id,actor_id,type,message) VALUES($1,$2,'tournament',$3)`,[r.rows[0].captain_user_id,String(req.user.id),`Your team ${r.rows[0].team_name} registration was ${mapped}. ${note}`]); res.json({team:r.rows[0]}); } catch(e){next(e);}
});

// Team registration listing for user-facing tournament detail pages.
app.get("/api/tournament/tournaments/:id/teams", async (req,res,next)=>{
  try { const id=Number.parseInt(req.params.id,10); if(!Number.isSafeInteger(id)||id<1)return res.status(400).json({error:"Invalid tournament ID."}); const r=await pool.query(`SELECT id::text AS id,team_name,players,status,created_at FROM ft_tournament_teams WHERE tournament_id=$1 AND status='approved' ORDER BY created_at`,[id]); res.json({teams:r.rows}); }
  catch(e){next(e);}
});

app.use((req, res) => {
  res.status(404).json({ error: "Route not found." });
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error.message === "Origin not allowed by CORS") {
    return res.status(403).json({ error: "Origin not allowed." });
  }
  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      error: error.code === "LIMIT_FILE_SIZE"
        ? "File is too large. Maximum size is 50 MB."
        : "Upload failed. Check the file and try again."
    });
  }
  if (error.message && error.message.startsWith("Unsupported file type")) {
    return res.status(400).json({ error: error.message });
  }

  console.error("Request failed:", {
    code: error.code,
    message: error.message
  });
  res.status(500).json({ error: "Internal server error." });
});

async function startServer() {
  try {
    if (pool) {
      await initializeDatabase();
      setInterval(() => purgeExpiredMessages().catch(e => console.error("Message cleanup failed:", e.message)), 5 * 60 * 1000).unref();
      await purgeExpiredMessages().catch(e => console.error("Initial message cleanup failed:", e.message));
    }
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`FreeTube API listening on port ${PORT}`);
    });
  } catch (e) {
    console.error("Startup failed:", e.message);
    process.exit(1);
  }
}

async function shutdown() {
  if (pool) await pool.end().catch(() => {});
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
startServer();
