require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const { Pool } = require("pg");
const crypto = require("crypto");
const { promisify } = require("util");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;

const scryptAsync = promisify(crypto.scrypt);
const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.disable("x-powered-by");
app.use(helmet());

const allowedOrigins = (process.env.FRONTEND_ORIGIN || "")
  .split(",").map(origin => origin.trim()).filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "100kb" }));

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
  pool.on("error", error => {
    console.error("Database pool error:", error.message);
  });
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
    const allowed = [
      "image/jpeg", "image/png", "image/webp", "image/gif",
      "video/mp4", "video/webm", "video/quicktime"
    ];

    if (!allowed.includes(file.mimetype)) {
      return callback(new Error(
        "Unsupported file type. Use JPG, PNG, WEBP, GIF, MP4 or WEBM."
      ));
    }

    callback(null, true);
  }
});

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
      error: "Authentication is not configured on the server."
    });
    return false;
  }

  return true;
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

    const storedKey = Buffer.from(parts[2], "hex");
    if (storedKey.length !== 64) return false;

    const derivedKey = await scryptAsync(password, parts[1], 64);
    return crypto.timingSafeEqual(storedKey, derivedKey);
  } catch (_) {
    return false;
  }
}

function createToken(user) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: String(user.id),
    username: user.username,
    role: user.role,
    iat: now,
    exp: now + 60 * 60 * 24 * 7
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

  let actual;
  try {
    actual = Buffer.from(supplied, "base64url");
  } catch (_) {
    return null;
  }

  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) return null;

  try {
    const payload = JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8")
    );

    if (
      !payload.sub ||
      !Number.isInteger(payload.exp) ||
      payload.exp <= Math.floor(Date.now() / 1000)
    ) return null;

    return payload;
  } catch (_) {
    return null;
  }
}

async function requireAuth(req, res, next) {
  if (!authReady(res)) return;

  const match = (req.get("authorization") || "")
    .match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({ error: "Authentication required." });
  }

  const payload = verifyToken(match[1]);
  if (!payload) {
    return res.status(401).json({
      error: "Invalid or expired access token."
    });
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

    if (result.rows[0].account_status !== "active") {
      return res.status(403).json({
        error: "This account is not active."
      });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    next(error);
  }
}

function cleanText(value, maxLength = 2000) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function makeUsernameBase(fullName) {
  let username = String(fullName || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .replace(/_+/g, "_")
    .slice(0, 40)
    .replace(/_+$/g, "");

  if (username.length < 3) username = "user";
  return username;
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

function isCloudinaryUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" &&
      parsed.hostname === "res.cloudinary.com" &&
      parsed.pathname.split("/").filter(Boolean).length >= 3;
  } catch (_) {
    return false;
  }
}

function checkFileSignature(buffer, mimetype) {
  if (!buffer || buffer.length < 12) return false;

  if (mimetype === "image/jpeg") {
    return buffer[0] === 0xff &&
      buffer[1] === 0xd8 &&
      buffer[2] === 0xff;
  }

  if (mimetype === "image/png") {
    return buffer.subarray(0, 8).equals(
      Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])
    );
  }

  if (mimetype === "image/gif") {
    return ["GIF87a", "GIF89a"].includes(
      buffer.subarray(0, 6).toString("ascii")
    );
  }

  if (mimetype === "image/webp") {
    return buffer.subarray(0, 4).toString("ascii") === "RIFF" &&
      buffer.subarray(8, 12).toString("ascii") === "WEBP";
  }

  if (
    mimetype === "video/mp4" ||
    mimetype === "video/quicktime"
  ) {
    return buffer.subarray(4, 8).toString("ascii") === "ftyp";
  }

  if (mimetype === "video/webm") {
    return buffer.subarray(0, 4).equals(
      Buffer.from([0x1a, 0x45, 0xdf, 0xa3])
    );
  }

  return false;
}

function sendCloudinaryUpload(buffer, mimetype) {
  return new Promise((resolve, reject) => {
    const resourceType = mimetype.startsWith("video/")
      ? "video"
      : "image";

    const stream = cloudinary.uploader.upload_stream(
      { folder: "freetube", resource_type: resourceType },
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

// Database initialization. Existing user data is preserved.
async function initializeDatabase() {
  if (!pool) return;

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ft_profiles (
      user_id TEXT PRIMARY KEY,
      display_name VARCHAR(80),
      bio VARCHAR(500),
      avatar_url TEXT,
      cover_url TEXT,
      city VARCHAR(120),
      home VARCHAR(200),
      birthday DATE,
      work VARCHAR(200),
      education VARCHAR(200),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS city VARCHAR(120);
    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS home VARCHAR(200);
    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS birthday DATE;
    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS work VARCHAR(200);
    ALTER TABLE ft_profiles ADD COLUMN IF NOT EXISTS education VARCHAR(200);

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
      PRIMARY KEY (post_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS ft_post_reactions (
      post_id BIGINT NOT NULL REFERENCES ft_posts(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      reaction VARCHAR(20) NOT NULL
        CHECK (reaction IN ('like', 'love', 'sad', 'angry')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (post_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS ft_post_views (
      post_id BIGINT NOT NULL REFERENCES ft_posts(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      viewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (post_id, user_id)
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
      PRIMARY KEY (follower_id, following_id),
      CHECK (follower_id <> following_id)
    );

    CREATE TABLE IF NOT EXISTS ft_post_reports (
      id BIGSERIAL PRIMARY KEY,
      post_id BIGINT NOT NULL REFERENCES ft_posts(id) ON DELETE CASCADE,
      reporter_id TEXT NOT NULL,
      reason VARCHAR(500) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'reviewed', 'dismissed')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (post_id, reporter_id)
    );

    CREATE INDEX IF NOT EXISTS ft_posts_created_idx
      ON ft_posts(created_at DESC);
    CREATE INDEX IF NOT EXISTS ft_posts_user_idx
      ON ft_posts(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS ft_comments_post_idx
      ON ft_comments(post_id, created_at);
    CREATE INDEX IF NOT EXISTS ft_messages_pair_idx
      ON ft_messages(sender_id, recipient_id, created_at);
    CREATE INDEX IF NOT EXISTS ft_notifications_recipient_idx
      ON ft_notifications(recipient_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS ft_follows_following_idx
      ON ft_follows(following_id);
    CREATE INDEX IF NOT EXISTS ft_post_reactions_post_idx
      ON ft_post_reactions(post_id);
    CREATE INDEX IF NOT EXISTS ft_post_views_post_idx
      ON ft_post_views(post_id);
  `);

  console.log("FreeTube database initialized.");
}

// Health.
app.get("/", (req, res) => {
  res.json({
    name: "FreeTube Backend API",
    status: "running",
    version: "3.2.0"
  });
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
  } catch (error) {
    next(error);
  }
});

app.get("/api", (req, res) => {
  res.json({
    message: "Welcome to FreeTube API",
    endpoints: [
      "POST /api/auth/register",
      "POST /api/auth/login",
      "GET /api/auth/me",
      "GET /api/profile",
      "GET /api/profile/:username",
      "PUT /api/profile",
      "GET /api/users/search?q=username",
      "POST /api/media/upload",
      "GET /api/posts",
      "POST /api/posts",
      "PUT /api/posts/:id",
      "DELETE /api/posts/:id",
      "POST /api/posts/:id/like",
      "PUT /api/posts/:id/reaction",
      "POST /api/posts/:id/view",
      "GET /api/posts/:id/comments",
      "POST /api/posts/:id/comments",
      "POST /api/posts/:id/report",
      "POST /api/users/:id/follow",
      "DELETE /api/users/:id/follow",
      "GET /api/users/:id/followers",
      "GET /api/users/:id/following",
      "GET /api/messages/:userId",
      "POST /api/messages",
      "GET /api/messages",
      "GET /api/notifications",
      "PATCH /api/notifications/:id/read",
      "PATCH /api/notifications/read-all"
    ]
  });
});

// Register.
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
      return res.status(400).json({
        error: "Full name must contain at least 2 characters."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }

    const passwordBytes = Buffer.byteLength(password, "utf8");
    if (passwordBytes < 8 || passwordBytes > 128) {
      return res.status(400).json({
        error: "Password must be 8-128 bytes long."
      });
    }

    const baseUsername = makeUsernameBase(fullName);
    const passwordHash = await hashPassword(password);

    client = await pool.connect();
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
      baseUsername
    ]);

    const existingEmail = await client.query(
      `SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [email]
    );

    if (existingEmail.rows.length) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "This email is already registered."
      });
    }

    let user = null;

    for (let attempt = 0; attempt < 100; attempt++) {
      const suffix = attempt === 0 ? "" : String(attempt + 1);
      const username =
        baseUsername.slice(0, 50 - suffix.length) + suffix;

      await client.query("SAVEPOINT username_attempt");

      try {
        const result = await client.query(
          `INSERT INTO users
           (username, email, password_hash, role, account_status)
           VALUES ($1, $2, $3, 'creator', 'active')
           RETURNING id, username, email, role, account_status, created_at`,
          [username, email, passwordHash]
        );

        user = result.rows[0];
        await client.query("RELEASE SAVEPOINT username_attempt");
        break;
      } catch (error) {
        await client.query("ROLLBACK TO SAVEPOINT username_attempt");
        await client.query("RELEASE SAVEPOINT username_attempt");
        if (error.code !== "23505") throw error;

        const duplicateEmail = await client.query(
          `SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1`,
          [email]
        );

        if (duplicateEmail.rows.length) {
          await client.query("ROLLBACK");
          return res.status(409).json({
            error: "This email is already registered."
          });
        }
      }
    }

    if (!user) {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "Could not generate a unique username."
      });
    }

    await client.query(
      `INSERT INTO ft_profiles (user_id, display_name)
       VALUES ($1, $2) ON CONFLICT (user_id) DO NOTHING`,
      [String(user.id), fullName]
    );

    await client.query("COMMIT");

    res.status(201).json({
      message: "Account created successfully.",
      token: createToken(user),
      user: { ...publicUser(user), display_name: fullName }
    });
  } catch (error) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    next(error);
  } finally {
    if (client) client.release();
  }
});

// Login.
app.post("/api/auth/login", async (req, res, next) => {
  if (!authReady(res)) return;

  try {
    const identifier = cleanText(
      req.body.identifier || req.body.email || req.body.username, 255
    );
    const password = typeof req.body.password === "string"
      ? req.body.password : "";

    if (!identifier || !password) {
      return res.status(400).json({
        error: "Enter your email or username and password."
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
        error: "Invalid username/email or password."
      });
    }

    if (user.account_status !== "active") {
      return res.status(403).json({
        error: "This account is not active."
      });
    }

    await pool.query(
      `INSERT INTO ft_profiles (user_id, display_name)
       VALUES ($1, $2) ON CONFLICT (user_id) DO NOTHING`,
      [String(user.id), user.username]
    );

    res.json({
      message: "Login successful.",
      token: createToken(user),
      user: publicUser(user)
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// Search users.
app.get("/api/users/search", requireAuth, async (req, res, next) => {
  try {
    const q = cleanText(req.query.q, 50);
    if (q.length < 2) return res.json({ users: [] });

    const result = await pool.query(
      `SELECT u.id, u.username, p.display_name, p.avatar_url
       FROM users u
       LEFT JOIN ft_profiles p ON p.user_id = u.id::text
       WHERE u.account_status = 'active'
         AND u.id::text <> $1
         AND LOWER(u.username) LIKE LOWER($2)
       ORDER BY u.username LIMIT 20`,
      [String(req.user.id), `%${q}%`]
    );

    res.json({ users: result.rows });
  } catch (error) {
    next(error);
  }
});

// Own profile.
app.get("/api/profile", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.username, u.email, u.role, u.created_at,
              p.display_name, p.bio, p.avatar_url, p.cover_url,
              p.city, p.home, p.birthday, p.work, p.education,
              p.updated_at,
              (SELECT COUNT(*) FROM ft_posts x
               WHERE x.user_id = u.id::text)::int AS posts_count,
              (SELECT COUNT(*) FROM ft_follows f
               WHERE f.following_id = u.id::text)::int AS followers_count,
              (SELECT COUNT(*) FROM ft_follows f
               WHERE f.follower_id = u.id::text)::int AS following_count
       FROM users u
       LEFT JOIN ft_profiles p ON p.user_id = u.id::text
       WHERE u.id::text = $1 LIMIT 1`,
      [String(req.user.id)]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Profile not found." });
    }

    res.json({ profile: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

// Public profile.
app.get("/api/profile/:username", async (req, res, next) => {
  if (!authReady(res)) return;

  try {
    const username = cleanText(req.params.username, 50);
    const authMatch = (req.get("authorization") || "")
      .match(/^Bearer\s+(.+)$/i);
    const payload = authMatch ? verifyToken(authMatch[1]) : null;
    const viewerId = payload ? String(payload.sub) : "";

    const result = await pool.query(
      `SELECT u.id, u.username, p.display_name, p.bio,
              p.avatar_url, p.cover_url, p.city, p.home,
              p.birthday, p.work, p.education, p.updated_at
       FROM users u
       LEFT JOIN ft_profiles p ON p.user_id = u.id::text
       WHERE LOWER(u.username) = LOWER($1)
         AND u.account_status = 'active'
       LIMIT 1`,
      [username]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "User not found." });
    }

    const profile = result.rows[0];
    const userId = String(profile.id);

    const [statsResult, followResult] = await Promise.all([
      pool.query(
        `SELECT
           (SELECT COUNT(*) FROM ft_posts WHERE user_id = $1)::int AS posts,
           (SELECT COUNT(*) FROM ft_likes l
            JOIN ft_posts p ON p.id = l.post_id
            WHERE p.user_id = $1)::int AS likes,
           (SELECT COUNT(*) FROM ft_follows
            WHERE following_id = $1)::int AS followers,
           (SELECT COUNT(*) FROM ft_follows
            WHERE follower_id = $1)::int AS following`,
        [userId]
      ),
      viewerId && viewerId !== userId
        ? pool.query(
            `SELECT 1 FROM ft_follows
             WHERE follower_id = $1 AND following_id = $2`,
            [viewerId, userId]
          )
        : Promise.resolve({ rows: [] })
    ]);

    const stats = statsResult.rows[0];

    profile.is_following = Boolean(followResult.rows.length);
    profile.is_own_profile = Boolean(viewerId && viewerId === userId);

    // Counts are available both in profile and in stats for frontend compatibility.
    profile.posts_count = Number(stats.posts);
    profile.likes_count = Number(stats.likes);
    profile.followers_count = Number(stats.followers);
    profile.following_count = Number(stats.following);

    res.json({ profile, user: profile, stats });
  } catch (error) {
    next(error);
  }
});

// Update profile.
app.put("/api/profile", requireAuth, async (req, res, next) => {
  try {
    const displayName = cleanText(req.body.display_name, 80);
    const bio = cleanText(req.body.bio, 500);
    const avatarUrl = cleanText(req.body.avatar_url, 2000);
    const coverUrl = cleanText(req.body.cover_url, 2000);
    const city = cleanText(req.body.city, 120);
    const home = cleanText(req.body.home, 200);
    const work = cleanText(req.body.work, 200);
    const education = cleanText(req.body.education, 200);
    const birthdayInput = cleanText(req.body.birthday, 10);

    for (const url of [avatarUrl, coverUrl]) {
      if (url && !isCloudinaryUrl(url)) {
        return res.status(400).json({
          error: "Profile images must use a valid Cloudinary HTTPS URL."
        });
      }
    }

    let birthday = null;

    if (birthdayInput) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(birthdayInput)) {
        return res.status(400).json({
          error: "Birthday must use YYYY-MM-DD format."
        });
      }

      const parsed = new Date(`${birthdayInput}T00:00:00.000Z`);
      if (
        Number.isNaN(parsed.getTime()) ||
        parsed.toISOString().slice(0, 10) !== birthdayInput
      ) {
        return res.status(400).json({ error: "Enter a valid birthday." });
      }

      if (birthdayInput > new Date().toISOString().slice(0, 10)) {
        return res.status(400).json({
          error: "Birthday cannot be in the future."
        });
      }

      birthday = birthdayInput;
    }

    const result = await pool.query(
      `INSERT INTO ft_profiles
       (user_id, display_name, bio, avatar_url, cover_url,
        city, home, birthday, work, education, updated_at)
       VALUES (
         $1, COALESCE(NULLIF($2, ''), $3), $4,
         NULLIF($5, ''), NULLIF($6, ''),
         $7, $8, $9::date, $10, $11, NOW()
       )
       ON CONFLICT (user_id) DO UPDATE SET
         display_name = CASE WHEN $12::boolean
           THEN EXCLUDED.display_name ELSE ft_profiles.display_name END,
         bio = CASE WHEN $13::boolean
           THEN EXCLUDED.bio ELSE ft_profiles.bio END,
         avatar_url = CASE WHEN $14::boolean
           THEN EXCLUDED.avatar_url ELSE ft_profiles.avatar_url END,
         cover_url = CASE WHEN $15::boolean
           THEN EXCLUDED.cover_url ELSE ft_profiles.cover_url END,
         city = CASE WHEN $16::boolean
           THEN EXCLUDED.city ELSE ft_profiles.city END,
         home = CASE WHEN $17::boolean
           THEN EXCLUDED.home ELSE ft_profiles.home END,
         birthday = CASE WHEN $18::boolean
           THEN EXCLUDED.birthday ELSE ft_profiles.birthday END,
         work = CASE WHEN $19::boolean
           THEN EXCLUDED.work ELSE ft_profiles.work END,
         education = CASE WHEN $20::boolean
           THEN EXCLUDED.education ELSE ft_profiles.education END,
         updated_at = NOW()
       RETURNING *`,
      [
        String(req.user.id), displayName, req.user.username, bio,
        avatarUrl, coverUrl, city, home, birthday, work, education,
        Object.prototype.hasOwnProperty.call(req.body, "display_name"),
        Object.prototype.hasOwnProperty.call(req.body, "bio"),
        Object.prototype.hasOwnProperty.call(req.body, "avatar_url"),
        Object.prototype.hasOwnProperty.call(req.body, "cover_url"),
        Object.prototype.hasOwnProperty.call(req.body, "city"),
        Object.prototype.hasOwnProperty.call(req.body, "home"),
        Object.prototype.hasOwnProperty.call(req.body, "birthday"),
        Object.prototype.hasOwnProperty.call(req.body, "work"),
        Object.prototype.hasOwnProperty.call(req.body, "education")
      ]
    );

    res.json({ message: "Profile updated.", profile: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

// Upload media.
app.post(
  "/api/media/upload",
  requireAuth,
  (req, res, next) => {
    if (!cloudinaryConfigured) {
      return res.status(503).json({
        error: "Cloudinary is not configured on the server."
      });
    }
    next();
  },
  (req, res, next) => {
    upload.single("file")(req, res, error => {
      if (error) return next(error);
      next();
    });
  },
  async (req, res, next) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: 'Choose a file using the "file" field.'
        });
      }

      if (!checkFileSignature(req.file.buffer, req.file.mimetype)) {
        return res.status(400).json({
          error: "File content does not match its declared type."
        });
      }

      const media = await sendCloudinaryUpload(
        req.file.buffer, req.file.mimetype
      );
      res.status(201).json({ media });
    } catch (error) {
      next(error);
    }
  }
);

// Create post.
app.post("/api/posts", requireAuth, async (req, res, next) => {
  try {
    const content = cleanText(req.body.content, 5000);
    const mediaUrl = cleanText(req.body.media_url, 2000);
    const mediaType = cleanText(req.body.media_type, 20);
    const mediaPublicId = cleanText(req.body.media_public_id, 255);

    if (!content && !mediaUrl) {
      return res.status(400).json({
        error: "Write something or attach media to create a post."
      });
    }

    if (mediaUrl && !isCloudinaryUrl(mediaUrl)) {
      return res.status(400).json({
        error: "Post media must use a valid Cloudinary HTTPS URL."
      });
    }

    if (mediaType && !["image", "video"].includes(mediaType)) {
      return res.status(400).json({ error: "Invalid media type." });
    }

    const result = await pool.query(
      `INSERT INTO ft_posts
       (user_id, content, media_url, media_type, media_public_id)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [
        String(req.user.id), content, mediaUrl || null,
        mediaType || null, mediaPublicId || null
      ]
    );

    res.status(201).json({
      message: "Post created.", post: result.rows[0]
    });
  } catch (error) {
    next(error);
  }
});

// Feed with like, reaction and view counts.
app.get("/api/posts", async (req, res, next) => {
  if (!authReady(res)) return;

  try {
    const limit = Math.min(
      50, Math.max(1, Number.parseInt(req.query.limit, 10) || 20)
    );
    const before = Number.parseInt(req.query.before, 10);
    const match = (req.headers.authorization || "")
      .match(/^Bearer\s+(.+)$/i);
    const payload = match ? verifyToken(match[1]) : null;
    const viewerId = payload ? String(payload.sub) : "";

    const result = await pool.query(
      `SELECT p.id, p.user_id, p.content, p.media_url, p.media_type,
              p.created_at, u.username,
              pr.display_name, pr.avatar_url,
              (SELECT COUNT(*)::int FROM ft_likes l
               WHERE l.post_id = p.id) AS like_count,
              (SELECT COUNT(*)::int FROM ft_comments c
               WHERE c.post_id = p.id) AS comment_count,
              (SELECT COUNT(*)::int FROM ft_post_views v
               WHERE v.post_id = p.id) AS view_count,
              EXISTS (
                SELECT 1 FROM ft_likes l
                WHERE l.post_id = p.id AND l.user_id = $2
              ) AS liked_by_me,
              (SELECT r.reaction FROM ft_post_reactions r
               WHERE r.post_id = p.id AND r.user_id = $2
               LIMIT 1) AS my_reaction,
              COALESCE((
                SELECT jsonb_object_agg(rc.reaction, rc.total)
                FROM (
                  SELECT reaction, COUNT(*)::int AS total
                  FROM ft_post_reactions
                  WHERE post_id = p.id
                  GROUP BY reaction
                ) rc
              ), '{"like":0,"love":0,"sad":0,"angry":0}'::jsonb)
                AS reaction_counts
       FROM ft_posts p
       JOIN users u ON u.id::text = p.user_id
       LEFT JOIN ft_profiles pr ON pr.user_id = p.user_id
       WHERE u.account_status = 'active'
         AND ($1::bigint IS NULL OR p.id < $1)
       ORDER BY p.id DESC LIMIT $3`,
      [
        Number.isSafeInteger(before) && before > 0 ? before : null,
        viewerId,
        limit
      ]
    );

    res.json({ posts: result.rows });
  } catch (error) {
    next(error);
  }
});

// Edit own post.
app.put("/api/posts/:id", requireAuth, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const content = cleanText(req.body.content, 5000);
    const mediaUrl = cleanText(req.body.media_url, 2000);
    const mediaType = cleanText(req.body.media_type, 20);

    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({ error: "Invalid post ID." });
    }

    if (!content && !mediaUrl) {
      return res.status(400).json({
        error: "A post must contain text or media."
      });
    }

    if (mediaUrl && !isCloudinaryUrl(mediaUrl)) {
      return res.status(400).json({
        error: "Post media must use a valid Cloudinary HTTPS URL."
      });
    }

    if (mediaType && !["image", "video"].includes(mediaType)) {
      return res.status(400).json({ error: "Invalid media type." });
    }

    const result = await pool.query(
      `UPDATE ft_posts SET content = $1, media_url = $2, media_type = $3
       WHERE id = $4 AND user_id = $5 RETURNING *`,
      [content, mediaUrl || null, mediaType || null, id, String(req.user.id)]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Post not found or you do not own this post."
      });
    }

    res.json({ message: "Post updated.", post: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

// Delete own post.
app.delete("/api/posts/:id", requireAuth, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);

    if (!Number.isSafeInteger(id) || id <= 0) {
      return res.status(400).json({ error: "Invalid post ID." });
    }

    const result = await pool.query(
      `DELETE FROM ft_posts WHERE id = $1 AND user_id = $2 RETURNING id`,
      [id, String(req.user.id)]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Post not found or you do not own this post."
      });
    }

    res.json({ message: "Post deleted.", id: result.rows[0].id });
  } catch (error) {
    next(error);
  }
});

// Like/unlike. Kept for compatibility with the existing frontend.
app.post("/api/posts/:id/like", requireAuth, async (req, res, next) => {
  const postId = Number.parseInt(req.params.id, 10);
  if (!Number.isSafeInteger(postId) || postId <= 0) {
    return res.status(400).json({ error: "Invalid post ID." });
  }

  let client;

  try {
    client = await pool.connect();
    await client.query("BEGIN");

    const post = await client.query(
      "SELECT id, user_id FROM ft_posts WHERE id = $1 FOR UPDATE",
      [postId]
    );

    if (!post.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Post not found." });
    }

    const userId = String(req.user.id);
    const existing = await client.query(
      "SELECT 1 FROM ft_likes WHERE post_id = $1 AND user_id = $2",
      [postId, userId]
    );

    let liked;

    if (existing.rows.length) {
      await client.query(
        "DELETE FROM ft_likes WHERE post_id = $1 AND user_id = $2",
        [postId, userId]
      );
      liked = false;
    } else {
      await client.query(
        "INSERT INTO ft_likes (post_id, user_id) VALUES ($1, $2)",
        [postId, userId]
      );
      liked = true;

      if (post.rows[0].user_id !== userId) {
        await client.query(
          `INSERT INTO ft_notifications
           (recipient_id, actor_id, type, post_id, message)
           VALUES ($1, $2, 'like', $3, $4)`,
          [
            post.rows[0].user_id, userId, postId,
            `${req.user.username} liked your post.`
          ]
        );
      }
    }

    const count = await client.query(
      "SELECT COUNT(*)::int AS count FROM ft_likes WHERE post_id = $1",
      [postId]
    );

    await client.query("COMMIT");
    res.json({ liked, like_count: count.rows[0].count });
  } catch (error) {
    if (client) await client.query("ROLLBACK").catch(() => {});
    next(error);
  } finally {
    if (client) client.release();
  }
});

// Add/change/remove a reaction.
app.put("/api/posts/:id/reaction", requireAuth, async (req, res, next) => {
  const postId = Number.parseInt(req.params.id, 10);
  const userId = String(req.user.id);
  const allowed = ["like", "love", "sad", "angry"];
  const reaction = cleanText(req.body.reaction, 20).toLowerCase();

  if (!Number.isSafeInteger(postId) || postId <= 0) {
    return res.status(400).json({ error: "Invalid post ID." });
  }

  if (reaction && !allowed.includes(reaction)) {
    return res.status(400).json({ error: "Invalid reaction." });
  }

  try {
    const post = await pool.query(
      "SELECT id, user_id FROM ft_posts WHERE id = $1",
      [postId]
    );

    if (!post.rows.length) {
      return res.status(404).json({ error: "Post not found." });
    }

    if (reaction) {
      await pool.query(
        `INSERT INTO ft_post_reactions (post_id, user_id, reaction)
         VALUES ($1, $2, $3)
         ON CONFLICT (post_id, user_id)
         DO UPDATE SET reaction = EXCLUDED.reaction, created_at = NOW()`,
        [postId, userId, reaction]
      );

      if (post.rows[0].user_id !== userId) {
        await pool.query(
          `INSERT INTO ft_notifications
           (recipient_id, actor_id, type, post_id, message)
           VALUES ($1, $2, 'reaction', $3, $4)`,
          [
            post.rows[0].user_id, userId, postId,
            `${req.user.username} reacted to your post.`
          ]
        );
      }
    } else {
      await pool.query(
        `DELETE FROM ft_post_reactions
         WHERE post_id = $1 AND user_id = $2`,
        [postId, userId]
      );
    }

    const countsResult = await pool.query(
      `SELECT reaction, COUNT(*)::int AS count
       FROM ft_post_reactions WHERE post_id = $1 GROUP BY reaction`,
      [postId]
    );

    const reaction_counts = { like: 0, love: 0, sad: 0, angry: 0 };
    for (const row of countsResult.rows) {
      reaction_counts[row.reaction] = row.count;
    }

    res.json({
      success: true,
      my_reaction: reaction || null,
      reaction_counts,
      like_count: reaction_counts.like
    });
  } catch (error) {
    next(error);
  }
});

// Record a view. A user is counted once per post.
app.post("/api/posts/:id/view", requireAuth, async (req, res, next) => {
  const postId = Number.parseInt(req.params.id, 10);
  const userId = String(req.user.id);

  if (!Number.isSafeInteger(postId) || postId <= 0) {
    return res.status(400).json({ error: "Invalid post ID." });
  }

  try {
    const post = await pool.query(
      "SELECT id FROM ft_posts WHERE id = $1",
      [postId]
    );

    if (!post.rows.length) {
      return res.status(404).json({ error: "Post not found." });
    }

    await pool.query(
      `INSERT INTO ft_post_views (post_id, user_id)
       VALUES ($1, $2)
       ON CONFLICT (post_id, user_id)
       DO UPDATE SET viewed_at = NOW()`,
      [postId, userId]
    );

    const count = await pool.query(
      `SELECT COUNT(*)::int AS view_count
       FROM ft_post_views WHERE post_id = $1`,
      [postId]
    );

    res.json({ success: true, view_count: count.rows[0].view_count });
  } catch (error) {
    next(error);
  }
});

// Read comments.
app.get("/api/posts/:id/comments", async (req, res, next) => {
  if (!authReady(res)) return;

  try {
    const postId = Number.parseInt(req.params.id, 10);
    if (!Number.isSafeInteger(postId) || postId <= 0) {
      return res.status(400).json({ error: "Invalid post ID." });
    }

    const result = await pool.query(
      `SELECT c.id, c.post_id, c.user_id, c.content, c.created_at,
              u.username, p.avatar_url
       FROM ft_comments c
       JOIN users u ON u.id::text = c.user_id
       LEFT JOIN ft_profiles p ON p.user_id = c.user_id
       WHERE c.post_id = $1 ORDER BY c.id ASC LIMIT 100`,
      [postId]
    );

    res.json({ comments: result.rows });
  } catch (error) {
    next(error);
  }
});

// Add comment.
app.post("/api/posts/:id/comments", requireAuth, async (req, res, next) => {
  try {
    const postId = Number.parseInt(req.params.id, 10);
    const content = cleanText(req.body.content, 2000);

    if (!Number.isSafeInteger(postId) || postId <= 0 || !content) {
      return res.status(400).json({
        error: "A valid post ID and comment are required."
      });
    }

    const post = await pool.query(
      "SELECT user_id FROM ft_posts WHERE id = $1", [postId]
    );

    if (!post.rows.length) {
      return res.status(404).json({ error: "Post not found." });
    }

    const result = await pool.query(
      `INSERT INTO ft_comments (post_id, user_id, content)
       VALUES ($1, $2, $3) RETURNING *`,
      [postId, String(req.user.id), content]
    );

    if (post.rows[0].user_id !== String(req.user.id)) {
      await pool.query(
        `INSERT INTO ft_notifications
         (recipient_id, actor_id, type, post_id, message)
         VALUES ($1, $2, 'comment', $3, $4)`,
        [
          post.rows[0].user_id, String(req.user.id), postId,
          `${req.user.username} commented on your post.`
        ]
      );
    }

    res.status(201).json({
      message: "Comment added.",
      comment: { ...result.rows[0], username: req.user.username }
    });
  } catch (error) {
    next(error);
  }
});

// Follow.
app.post("/api/users/:id/follow", requireAuth, async (req, res, next) => {
  try {
    const targetId = cleanText(req.params.id, 100);
    const myId = String(req.user.id);

    if (!targetId || targetId === myId) {
      return res.status(400).json({
        error: "You cannot follow yourself."
      });
    }

    const target = await pool.query(
      `SELECT id FROM users
       WHERE id::text = $1 AND account_status = 'active'`,
      [targetId]
    );

    if (!target.rows.length) {
      return res.status(404).json({ error: "User not found." });
    }

    const result = await pool.query(
      `INSERT INTO ft_follows (follower_id, following_id)
       VALUES ($1, $2)
       ON CONFLICT (follower_id, following_id) DO NOTHING
       RETURNING follower_id`,
      [myId, targetId]
    );

    if (result.rowCount > 0) {
      await pool.query(
        `INSERT INTO ft_notifications
         (recipient_id, actor_id, type, message)
         VALUES ($1, $2, 'follow', $3)`,
        [targetId, myId, `${req.user.username} started following you.`]
      );
    }

    res.json({
      following: true,
      already_following: result.rowCount === 0
    });
  } catch (error) {
    next(error);
  }
});

// Unfollow.
app.delete("/api/users/:id/follow", requireAuth, async (req, res, next) => {
  try {
    const targetId = cleanText(req.params.id, 100);
    const myId = String(req.user.id);

    if (!targetId || targetId === myId) {
      return res.status(400).json({ error: "Invalid user ID." });
    }

    const result = await pool.query(
      `DELETE FROM ft_follows
       WHERE follower_id = $1 AND following_id = $2
       RETURNING follower_id`,
      [myId, targetId]
    );

    res.json({
      following: false,
      unfollowed: result.rowCount > 0
    });
  } catch (error) {
    next(error);
  }
});

// Followers.
app.get("/api/users/:id/followers", async (req, res, next) => {
  if (!authReady(res)) return;

  try {
    const userId = cleanText(req.params.id, 100);
    const result = await pool.query(
      `SELECT u.id, u.username, p.display_name, p.avatar_url,
              f.created_at AS followed_at
       FROM ft_follows f
       JOIN users u ON u.id::text = f.follower_id
       LEFT JOIN ft_profiles p ON p.user_id = u.id::text
       WHERE f.following_id = $1 AND u.account_status = 'active'
       ORDER BY f.created_at DESC LIMIT 200`,
      [userId]
    );

    res.json({ followers: result.rows });
  } catch (error) {
    next(error);
  }
});

// Following.
app.get("/api/users/:id/following", async (req, res, next) => {
  if (!authReady(res)) return;

  try {
    const userId = cleanText(req.params.id, 100);
    const result = await pool.query(
      `SELECT u.id, u.username, p.display_name, p.avatar_url,
              f.created_at AS followed_at
       FROM ft_follows f
       JOIN users u ON u.id::text = f.following_id
       LEFT JOIN ft_profiles p ON p.user_id = u.id::text
       WHERE f.follower_id = $1 AND u.account_status = 'active'
       ORDER BY f.created_at DESC LIMIT 200`,
      [userId]
    );

    res.json({ following: result.rows });
  } catch (error) {
    next(error);
  }
});

// Report a post.
app.post("/api/posts/:id/report", requireAuth, async (req, res, next) => {
  try {
    const postId = Number.parseInt(req.params.id, 10);
    const reason = cleanText(req.body.reason, 500);

    if (!Number.isSafeInteger(postId) || postId <= 0 || !reason) {
      return res.status(400).json({
        error: "A valid post ID and report reason are required."
      });
    }

    const post = await pool.query(
      "SELECT id FROM ft_posts WHERE id = $1", [postId]
    );

    if (!post.rows.length) {
      return res.status(404).json({ error: "Post not found." });
    }

    const result = await pool.query(
      `INSERT INTO ft_post_reports (post_id, reporter_id, reason)
       VALUES ($1, $2, $3)
       ON CONFLICT (post_id, reporter_id) DO NOTHING
       RETURNING id`,
      [postId, String(req.user.id), reason]
    );

    res.status(201).json({
      message: result.rowCount
        ? "Report submitted for review."
        : "You have already reported this post.",
      reported: true
    });
  } catch (error) {
    next(error);
  }
});

// Read conversation.
app.get("/api/messages/:userId", requireAuth, async (req, res, next) => {
  try {
    const me = String(req.user.id);
    const other = cleanText(req.params.userId, 100);

    if (!other || other === me) {
      return res.status(400).json({ error: "Invalid conversation user." });
    }

    const account = await pool.query(
      `SELECT id FROM users
       WHERE id::text = $1 AND account_status = 'active'`,
      [other]
    );

    if (!account.rows.length) {
      return res.status(404).json({ error: "User not found." });
    }

    await pool.query(
      `UPDATE ft_messages SET read_at = NOW()
       WHERE sender_id = $1 AND recipient_id = $2 AND read_at IS NULL`,
      [other, me]
    );

    const result = await pool.query(
      `SELECT id, sender_id, recipient_id, content, created_at, read_at
       FROM ft_messages
       WHERE (sender_id = $1 AND recipient_id = $2)
          OR (sender_id = $2 AND recipient_id = $1)
       ORDER BY id DESC LIMIT 100`,
      [me, other]
    );

    res.json({ messages: result.rows.reverse() });
  } catch (error) {
    next(error);
  }
});

// Send message.
app.post("/api/messages", requireAuth, async (req, res, next) => {
  try {
    const recipientId = cleanText(req.body.recipient_id, 100);
    const content = cleanText(req.body.content, 5000);
    const senderId = String(req.user.id);

    if (!recipientId || recipientId === senderId || !content) {
      return res.status(400).json({
        error: "A valid recipient and message are required."
      });
    }

    const recipient = await pool.query(
      `SELECT id FROM users
       WHERE id::text = $1 AND account_status = 'active'`,
      [recipientId]
    );

    if (!recipient.rows.length) {
      return res.status(404).json({ error: "Recipient not found." });
    }

    const result = await pool.query(
      `INSERT INTO ft_messages (sender_id, recipient_id, content)
       VALUES ($1, $2, $3) RETURNING *`,
      [senderId, recipientId, content]
    );

    await pool.query(
      `INSERT INTO ft_notifications
       (recipient_id, actor_id, type, message)
       VALUES ($1, $2, 'message', $3)`,
      [recipientId, senderId, `New message from ${req.user.username}.`]
    );

    res.status(201).json({
      message: "Message sent.",
      item: result.rows[0]
    });
  } catch (error) {
    next(error);
  }
});

// List conversations.
app.get("/api/messages", requireAuth, async (req, res, next) => {
  try {
    const me = String(req.user.id);
    const result = await pool.query(
      `WITH conversation_messages AS (
         SELECT *,
           CASE WHEN sender_id = $1 THEN recipient_id ELSE sender_id END
             AS other_id
         FROM ft_messages
         WHERE sender_id = $1 OR recipient_id = $1
       ),
       latest AS (
         SELECT DISTINCT ON (other_id)
           other_id, id, sender_id, recipient_id, content, created_at
         FROM conversation_messages
         ORDER BY other_id, id DESC
       )
       SELECT l.*, u.username, p.display_name, p.avatar_url,
         (SELECT COUNT(*)::int FROM ft_messages m
          WHERE m.sender_id = l.other_id
            AND m.recipient_id = $1
            AND m.read_at IS NULL) AS unread_count
       FROM latest l
       JOIN users u ON u.id::text = l.other_id
       LEFT JOIN ft_profiles p ON p.user_id = l.other_id
       ORDER BY l.id DESC`,
      [me]
    );

    res.json({ conversations: result.rows });
  } catch (error) {
    next(error);
  }
});

// Notifications.
app.get("/api/notifications", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT n.*, u.username AS actor_username
       FROM ft_notifications n
       LEFT JOIN users u ON u.id::text = n.actor_id
       WHERE n.recipient_id = $1
       ORDER BY n.id DESC LIMIT 100`,
      [String(req.user.id)]
    );

    const unread = await pool.query(
      `SELECT COUNT(*)::int AS count FROM ft_notifications
       WHERE recipient_id = $1 AND read_at IS NULL`,
      [String(req.user.id)]
    );

    res.json({
      notifications: result.rows,
      unread_count: unread.rows[0].count
    });
  } catch (error) {
    next(error);
  }
});

// Mark one notification as read.
app.patch(
  "/api/notifications/:id/read",
  requireAuth,
  async (req, res, next) => {
    try {
      const id = Number.parseInt(req.params.id, 10);

      if (!Number.isSafeInteger(id) || id <= 0) {
        return res.status(400).json({
          error: "Invalid notification ID."
        });
      }

      const result = await pool.query(
        `UPDATE ft_notifications SET read_at = NOW()
         WHERE id = $1 AND recipient_id = $2
         RETURNING id, read_at`,
        [id, String(req.user.id)]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          error: "Notification not found."
        });
      }

      res.json({ notification: result.rows[0] });
    } catch (error) {
      next(error);
    }
  }
);

// Mark all notifications as read.
app.patch(
  "/api/notifications/read-all",
  requireAuth,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `UPDATE ft_notifications SET read_at = NOW()
         WHERE recipient_id = $1 AND read_at IS NULL`,
        [String(req.user.id)]
      );

      res.json({
        message: "Notifications marked as read.",
        updated: result.rowCount
      });
    } catch (error) {
      next(error);
    }
  }
);

// 404.
app.use((req, res) => {
  res.status(404).json({ error: "Route not found." });
});

// Error handling.
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

// Start.
async function startServer() {
  try {
    if (pool) await initializeDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`FreeTube API listening on port ${PORT}`);
    });
  } catch (error) {
    console.error("Startup failed:", error.message);
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