
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const Groq = require("groq-sdk");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const production = process.env.NODE_ENV === "production";

if (!process.env.DATABASE_URL ||
    !process.env.SESSION_SECRET ||
    !process.env.GROQ_API_KEY ||
    !process.env.ADMIN_EMAIL ||
    !process.env.ADMIN_PASSWORD) {
  console.error("Variables requises manquantes. Configure-les dans Render.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: production ? { rejectUnauthorized: false } : false
});

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY
});

app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: "30kb" }));
app.use(express.static(path.join(__dirname, "public")));

app.use(rateLimit({
  windowMs: 60 * 1000,
  limit: 40,
  standardHeaders: true,
  legacyHeaders: false
}));

app.use(session({
  store: new PgSession({
    pool,
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: production,
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Connecte-toi d'abord." });
  }
  next();
};

const requireAdmin = async (req, res, next) => {
  try {
    const result = await pool.query(
      "SELECT role, disabled FROM users WHERE id = $1",
      [req.session.userId]
    );

    if (!result.rows[0] ||
        result.rows[0].role !== "admin" ||
        result.rows[0].disabled) {
      return res.status(403).json({ error: "Accès administrateur refusé." });
    }

    next();
  } catch (error) {
    next(error);
  }
};

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(40) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'user',
      premium BOOLEAN NOT NULL DEFAULT FALSE,
      disabled BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS conversations (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(120) NOT NULL DEFAULT 'Nouvelle conversation',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
      role VARCHAR(20) NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS daily_usage (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      usage_date DATE NOT NULL DEFAULT CURRENT_DATE,
      message_count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (user_id, usage_date)
    );
  `);

  const email = process.env.ADMIN_EMAIL.trim().toLowerCase();
  const passwordHash = await bcrypt.hash(
    process.env.ADMIN_PASSWORD,
    12
  );

  const existing = await pool.query(
    "SELECT id FROM users WHERE email = $1",
    [email]
  );

  if (existing.rowCount === 0) {
    await pool.query(
      `INSERT INTO users
       (username, email, password_hash, role)
       VALUES ($1, $2, $3, 'admin')`,
      ["AFK Admin", email, passwordHash]
    );
    console.log("Compte administrateur initial créé.");
  } else {
    console.log("Compte administrateur déjà présent.");
  }
}

app.get("/api/ping", (req, res) => {
  res.json({ status: "ok", name: "AFK AI" });
});

app.post("/api/register", async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (username.length < 2 || username.length > 40) {
      return res.status(400).json({
        error: "Le nom doit contenir entre 2 et 40 caractères."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Adresse e-mail invalide." });
    }

    if (password.length < 10 || password.length > 100) {
      return res.status(400).json({
        error: "Le mot de passe doit contenir au moins 10 caractères."
      });
    }

    if (email === process.env.ADMIN_EMAIL.trim().toLowerCase()) {
      return res.status(403).json({
        error: "Cette adresse est réservée à l'administration."
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, role, premium`,
      [username, email, hash]
    );

    req.session.userId = result.rows[0].id;
    res.status(201).json({ user: result.rows[0] });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Cette adresse e-mail est déjà utilisée." });
    }
    next(error);
  }
});

app.post("/api/login", async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "E-mail ou mot de passe incorrect." });
    }

    if (user.disabled) {
      return res.status(403).json({ error: "Ce compte est désactivé." });
    }

    req.session.regenerate((error) => {
      if (error) return next(error);
      req.session.userId = user.id;
      req.session.save((saveError) => {
        if (saveError) return next(saveError);
        res.json({
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            premium: user.premium
          }
        });
      });
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/logout", (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });
});

app.get("/api/me", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, username, email, role, premium
       FROM users WHERE id = $1 AND disabled = FALSE`,
      [req.session.userId]
    );

    if (!result.rows[0]) {
      return res.status(401).json({ error: "Compte indisponible." });
    }
    res.json({ user: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

app.get("/api/conversations", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, title, created_at FROM conversations
       WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100`,
      [req.session.userId]
    );
    res.json({ conversations: result.rows });
  } catch (error) {
    next(error);
  }
});

app.post("/api/conversations", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query(
      `INSERT INTO conversations (user_id, title)
       VALUES ($1, 'Nouvelle conversation')
       RETURNING id, title, created_at`,
      [req.session.userId]
    );
    res.status(201).json({ conversation: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

app.get("/api/conversations/:id/messages", requireAuth, async (req, res, next) => {
  try {
    const conversationId = Number(req.params.id);
    const owned = await pool.query(
      "SELECT id FROM conversations WHERE id = $1 AND user_id = $2",
      [conversationId, req.session.userId]
    );

    if (!owned.rowCount) {
      return res.status(404).json({ error: "Conversation introuvable." });
    }

    const result = await pool.query(
      `SELECT id, role, content, created_at FROM messages
       WHERE conversation_id = $1 ORDER BY id ASC LIMIT 200`,
      [conversationId]
    );
    res.json({ messages: result.rows });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/conversations/:id", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query(
      "DELETE FROM conversations WHERE id = $1 AND user_id = $2",
      [Number(req.params.id), req.session.userId]
    );
    if (!result.rowCount) {
      return res.status(404).json({ error: "Conversation introuvable." });
    }
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.post("/api/chat", requireAuth, async (req, res, next) => {
  try {
    const message = String(req.body.message || "").trim();
    let conversationId = Number(req.body.conversationId);

    if (!message || message.length > 8000) {
      return res.status(400).json({
        error: "Le message doit contenir entre 1 et 8000 caractères."
      });
    }

    const userResult = await pool.query(
      "SELECT role, premium, disabled FROM users WHERE id = $1",
      [req.session.userId]
    );
    const user = userResult.rows[0];

    if (!user || user.disabled) {
      return res.status(403).json({ error: "Compte indisponible." });
    }

    if (!conversationId) {
      const created = await pool.query(
        `INSERT INTO conversations (user_id, title)
         VALUES ($1, $2) RETURNING id`,
        [req.session.userId, message.slice(0, 60)]
      );
      conversationId = created.rows[0].id;
    }

    const owned = await pool.query(
      "SELECT id FROM conversations WHERE id = $1 AND user_id = $2",
      [conversationId, req.session.userId]
    );

    if (!owned.rowCount) {
      return res.status(404).json({ error: "Conversation introuvable." });
    }

    const limit = user.role === "admin" ? Infinity : user.premium ? 100 : 10;

    const usageResult = await pool.query(
      `INSERT INTO daily_usage (user_id, usage_date, message_count)
       VALUES ($1, CURRENT_DATE, 0)
       ON CONFLICT (user_id, usage_date) DO UPDATE
       SET message_count = daily_usage.message_count
       RETURNING message_count`,
      [req.session.userId]
    );

    if (usageResult.rows[0].message_count >= limit) {
      return res.status(429).json({
        error: user.premium
          ? "Tu as atteint ta limite quotidienne."
          : "Limite gratuite atteinte : 10 messages par jour."
      });
    }

    await pool.query(
      `UPDATE daily_usage SET message_count = message_count + 1
       WHERE user_id = $1 AND usage_date = CURRENT_DATE`,
      [req.session.userId]
    );

    await pool.query(
      "INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'user', $2)",
      [conversationId, message]
    );

    const historyResult = await pool.query(
      `SELECT role, content FROM (
         SELECT role, content, id FROM messages
         WHERE conversation_id = $1 ORDER BY id DESC LIMIT 20
       ) recent ORDER BY id ASC`,
      [conversationId]
    );

    try {
      const completion = await groq.chat.completions.create({
        model: process.env.GROQ_MODEL || "llama-3.3-70b-versatile",
        messages: [
          {
            role: "system",
            content: "Tu es AFK AI, un assistant utile, professionnel et respectueux. Réponds dans la langue utilisée par l'utilisateur."
          },
          ...historyResult.rows
        ],
        max_tokens: 1500,
        temperature: 0.7
      });

      const answer = completion.choices[0]?.message?.content ||
        "Désolé, je n'ai pas pu générer de réponse.";

      await pool.query(
        "INSERT INTO messages (conversation_id, role, content) VALUES ($1, 'assistant', $2)",
        [conversationId, answer]
      );

      res.json({
        answer,
        conversationId,
        remaining: user.role === "admin" ? null : Math.max(0, limit - usageResult.rows[0].message_count - 1)
      });
    } catch (error) {
      await pool.query(
        `UPDATE daily_usage SET message_count = GREATEST(0, message_count - 1)
         WHERE user_id = $1 AND usage_date = CURRENT_DATE`,
        [req.session.userId]
      );
      throw error;
    }
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/stats", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const [users, conversations, messages] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS count FROM users"),
      pool.query("SELECT COUNT(*)::int AS count FROM conversations"),
      pool.query("SELECT COUNT(*)::int AS count FROM messages")
    ]);

    res.json({
      users: users.rows[0].count,
      conversations: conversations.rows[0].count,
      messages: messages.rows[0].count
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/users", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, username, email, role, premium, disabled, created_at
       FROM users ORDER BY created_at DESC LIMIT 200`
    );
    res.json({ users: result.rows });
  } catch (error) {
    next(error);
  }
});

app.patch("/api/admin/users/:id", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const fields = [];
    const values = [];

    if (typeof req.body.premium === "boolean") {
      values.push(req.body.premium);
      fields.push(`premium = $${values.length}`);
    }

    if (typeof req.body.disabled === "boolean") {
      values.push(req.body.disabled);
      fields.push(`disabled = $${values.length}`);
    }

    if (!fields.length) {
      return res.status(400).json({ error: "Aucun changement valide." });
    }

    values.push(id);
    const result = await pool.query(
      `UPDATE users SET ${fields.join(", ")}
       WHERE id = $${values.length} AND role <> 'admin'
       RETURNING id, username, email, role, premium, disabled`,
      values
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Utilisateur introuvable ou protégé." });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

app.use("/api", (req, res) => {
  res.status(404).json({ error: "Route API introuvable." });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((error, req, res, next) => {
  console.error("Erreur serveur :", error.message);
  if (res.headersSent) return next(error);
  res.status(500).json({
    error: "Une erreur est survenue. Réessaie plus tard."
  });
});

initializeDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`AFK AI est lancé sur le port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Impossible de démarrer AFK AI :", error);
    process.exit(1);
  });
