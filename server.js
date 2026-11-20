
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { Server } = require("socket.io");

const app = express();
app.set("trust proxy", 1);
const server = http.createServer(app);
const io = new Server(server);

const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ADMIN_PASSWORD || !SESSION_SECRET ||
    ADMIN_PASSWORD.startsWith("RemplacePar") ||
    SESSION_SECRET.startsWith("RemplacePar")) {
  throw new Error("Configure ADMIN_PASSWORD et SESSION_SECRET dans .env");
}

const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const CONVERSATIONS_FILE = path.join(DATA_DIR, "conversations.json");

fs.mkdirSync(DATA_DIR, { recursive: true });

for (const file of [USERS_FILE, CONVERSATIONS_FILE]) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, "[]", "utf8");
}

function readJSON(file) {
  try {
    const value = JSON.parse(fs.readFileSync(file, "utf8"));
    if (!Array.isArray(value)) throw new Error("Format JSON invalide");
    return value;
  } catch (error) {
    console.error("Erreur de lecture :", file, error.message);
    throw new Error("Impossible de lire les données du serveur.");
  }
}

// Sérialise les écritures pour éviter que deux messages simultanés
// écrasent les modifications l'un de l'autre.
const writeQueues = new Map();

function writeJSON(file, data) {
  const previous = writeQueues.get(file) || Promise.resolve();

  const next = previous.then(async () => {
    const temp = file + "." + crypto.randomUUID() + ".tmp";
    await fs.promises.writeFile(temp, JSON.stringify(data, null, 2), "utf8");
    await fs.promises.rename(temp, file);
  });

  writeQueues.set(file, next.catch(() => {}));
  return next;
}

const sessionMiddleware = session({
  name: "support.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: "auto",
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

app.use(express.json({ limit: "20kb" }));
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public")));

io.engine.use(sessionMiddleware);

function requireUser(req, res, next) {
  if (!req.session.userId || req.session.role !== "user") {
    return res.status(401).json({ error: "Veuillez vous connecter." });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.role !== "admin") {
    return res.status(401).json({ error: "Accès administrateur refusé." });
  }
  next();
}

function clean(value, max = 2000) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt
  };
}

function publicConversation(conversation) {
  return {
    id: conversation.id,
    subject: conversation.subject,
    status: conversation.status,
    createdAt: conversation.createdAt,
    updatedAt: conversation.updatedAt,
    messages: conversation.messages
  };
}

function getUserConversation(id, userId) {
  return readJSON(CONVERSATIONS_FILE).find(
    c => c.id === id && c.userId === userId
  );
}

function emitConversationUpdate(conversation) {
  io.to("user:" + conversation.userId).emit("conversation:updated", {
    conversationId: conversation.id
  });
  io.to("admins").emit("conversation:updated", {
    conversationId: conversation.id
  });
}

function addMessage(conversation, sender, message) {
  const item = {
    id: crypto.randomUUID(),
    sender,
    message,
    createdAt: new Date().toISOString()
  };

  conversation.messages.push(item);
  conversation.updatedAt = item.createdAt;
  return item;
}

// ---------------- AUTHENTIFICATION ----------------

// Création de compte
app.post("/api/auth/register", async (req, res) => {
  try {
    const email = clean(req.body.email, 150).toLowerCase();
    const password = typeof req.body.password === "string"
      ? req.body.password : "";

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Adresse e-mail invalide." });
    }

    if (password.length < 8 || password.length > 100) {
      return res.status(400).json({
        error: "Le mot de passe doit contenir entre 8 et 100 caractères."
      });
    }

    const users = readJSON(USERS_FILE);

    if (users.some(u => u.email === email)) {
      return res.status(409).json({
        error: "Cette adresse e-mail possède déjà un compte."
      });
    }

    const user = {
      id: crypto.randomUUID(),
      email,
      passwordHash: await bcrypt.hash(password, 12),
      createdAt: new Date().toISOString()
    };

    users.push(user);
    await writeJSON(USERS_FILE, users);

    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "Erreur de session." });

      req.session.userId = user.id;
      req.session.role = "user";

      req.session.save(saveError => {
        if (saveError) return res.status(500).json({ error: "Erreur de session." });
        res.status(201).json({ user: publicUser(user) });
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Impossible de créer le compte." });
  }
});

// Connexion
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = clean(req.body.email, 150).toLowerCase();
    const password = typeof req.body.password === "string"
      ? req.body.password : "";

    const user = readJSON(USERS_FILE).find(u => u.email === email);

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({
        error: "Adresse e-mail ou mot de passe incorrect."
      });
    }

    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "Erreur de session." });

      req.session.userId = user.id;
      req.session.role = "user";

      req.session.save(saveError => {
        if (saveError) return res.status(500).json({ error: "Erreur de session." });
        res.json({ user: publicUser(user) });
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erreur pendant la connexion." });
  }
});

// Vérifier la session courante
app.get("/api/auth/me", (req, res) => {
  if (req.session.role === "admin") {
    return res.json({ role: "admin" });
  }

  if (req.session.role !== "user") {
    return res.status(401).json({ error: "Non connecté." });
  }

  const user = readJSON(USERS_FILE).find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: "Compte introuvable." });

  res.json({ role: "user", user: publicUser(user) });
});

// Déconnexion
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("support.sid");
    res.json({ ok: true });
  });
});

// ---------------- ADMINISTRATION ----------------

app.post("/api/admin/login", (req, res) => {
  const password = typeof req.body.password === "string"
    ? req.body.password : "";

  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Mot de passe incorrect." });
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Erreur de session." });

    req.session.role = "admin";
    req.session.save(saveError => {
      if (saveError) return res.status(500).json({ error: "Erreur de session." });
      res.json({ ok: true });
    });
  });
});

app.get("/api/admin/conversations", requireAdmin, (req, res) => {
  const users = readJSON(USERS_FILE);
  const conversations = readJSON(CONVERSATIONS_FILE);

  const result = conversations.map(c => {
    const user = users.find(u => u.id === c.userId);
    return {
      ...publicConversation(c),
      email: user ? user.email : "Compte supprimé",
      messageCount: c.messages.length
    };
  }).sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));

  res.json({ conversations: result, userCount: users.length });
});

app.get("/api/admin/users", requireAdmin, (req, res) => {
  const users = readJSON(USERS_FILE).map(publicUser);
  res.json({ users });
});

app.get("/api/admin/conversations/:id", requireAdmin, (req, res) => {
  const conversation = readJSON(CONVERSATIONS_FILE).find(
    c => c.id === req.params.id
  );

  if (!conversation) {
    return res.status(404).json({ error: "Conversation introuvable." });
  }

  const user = readJSON(USERS_FILE).find(u => u.id === conversation.userId);

  res.json({
    conversation: {
      ...publicConversation(conversation),
      email: user ? user.email : "Compte supprimé"
    }
  });
});

app.post("/api/admin/conversations/:id/messages", requireAdmin, async (req, res) => {
  try {
    const message = clean(req.body.message);
    if (!message) return res.status(400).json({ error: "Message vide." });

    const conversations = readJSON(CONVERSATIONS_FILE);
    const conversation = conversations.find(c => c.id === req.params.id);

    if (!conversation) {
      return res.status(404).json({ error: "Conversation introuvable." });
    }

    if (conversation.status === "closed") {
      return res.status(400).json({ error: "Cette conversation est clôturée." });
    }

    const item = addMessage(conversation, "admin", message);
    await writeJSON(CONVERSATIONS_FILE, conversations);
    emitConversationUpdate(conversation);

    res.status(201).json({ message: item });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Impossible d'envoyer le message." });
  }
});

app.post("/api/admin/conversations/:id/close", requireAdmin, async (req, res) => {
  try {
    const conversations = readJSON(CONVERSATIONS_FILE);
    const conversation = conversations.find(c => c.id === req.params.id);

    if (!conversation) {
      return res.status(404).json({ error: "Conversation introuvable." });
    }

    conversation.status = "closed";
    conversation.updatedAt = new Date().toISOString();

    await writeJSON(CONVERSATIONS_FILE, conversations);
    emitConversationUpdate(conversation);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: "Impossible de clôturer la conversation." });
  }
});

app.post("/api/admin/conversations/:id/reopen", requireAdmin, async (req, res) => {
  try {
    const conversations = readJSON(CONVERSATIONS_FILE);
    const conversation = conversations.find(c => c.id === req.params.id);

    if (!conversation) {
      return res.status(404).json({ error: "Conversation introuvable." });
    }

    conversation.status = "open";
    conversation.updatedAt = new Date().toISOString();

    await writeJSON(CONVERSATIONS_FILE, conversations);
    emitConversationUpdate(conversation);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: "Impossible de rouvrir la conversation." });
  }
});

// ---------------- ESPACE UTILISATEUR ----------------

app.get("/api/conversations", requireUser, (req, res) => {
  const conversations = readJSON(CONVERSATIONS_FILE)
    .filter(c => c.userId === req.session.userId)
    .map(publicConversation)
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));

  res.json({ conversations });
});

app.post("/api/conversations", requireUser, async (req, res) => {
  try {
    const subject = clean(req.body.subject, 100);
    const message = clean(req.body.message);

    if (!subject || !message) {
      return res.status(400).json({
        error: "Le sujet et le message sont obligatoires."
      });
    }

    const conversations = readJSON(CONVERSATIONS_FILE);
    const conversation = {
      id: crypto.randomUUID(),
      userId: req.session.userId,
      subject,
      status: "open",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      messages: []
    };

    addMessage(conversation, "user", message);
    conversations.push(conversation);

    await writeJSON(CONVERSATIONS_FILE, conversations);
    emitConversationUpdate(conversation);

    res.status(201).json({
      conversation: publicConversation(conversation)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Impossible de créer la conversation." });
  }
});

app.get("/api/conversations/:id", requireUser, (req, res) => {
  const conversation = getUserConversation(req.params.id, req.session.userId);

  if (!conversation) {
    return res.status(404).json({ error: "Conversation introuvable." });
  }

  res.json({ conversation: publicConversation(conversation) });
});

app.post("/api/conversations/:id/messages", requireUser, async (req, res) => {
  try {
    const message = clean(req.body.message);
    if (!message) return res.status(400).json({ error: "Message vide." });

    const conversations = readJSON(CONVERSATIONS_FILE);
    const conversation = conversations.find(
      c => c.id === req.params.id && c.userId === req.session.userId
    );

    if (!conversation) {
      return res.status(404).json({ error: "Conversation introuvable." });
    }

    if (conversation.status === "closed") {
      return res.status(400).json({ error: "Cette conversation est clôturée." });
    }

    const item = addMessage(conversation, "user", message);
    await writeJSON(CONVERSATIONS_FILE, conversations);
    emitConversationUpdate(conversation);

    res.status(201).json({ message: item });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Impossible d'envoyer le message." });
  }
});

// ---------------- SOCKET.IO ----------------

io.use((socket, next) => {
  const session = socket.request.session;

  if (!session || !session.role) {
    return next(new Error("Authentification nécessaire."));
  }

  if (session.role === "user" && session.userId) return next();
  if (session.role === "admin") return next();

  next(new Error("Accès refusé."));
});

io.on("connection", socket => {
  const session = socket.request.session;

  if (session.role === "admin") {
    socket.join("admins");
  } else if (session.role === "user") {
    socket.join("user:" + session.userId);
  }
});

// ---------------- ERREURS ----------------

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Erreur interne du serveur." });
});

server.listen(PORT, () => {
  console.log("Serveur démarré sur le port " + PORT);
});
