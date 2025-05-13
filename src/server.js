const https = require("https");
const fs = require("fs");
const express = require("express");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fetch = require("node-fetch");
const winston = require("winston");
const morgan = require("morgan");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();

// Configuration
const RECAPTCHA_SECRET = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"; // Test key Google

// Logger Winston
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} [${level}]: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/messages.log' }),
    new winston.transports.File({ filename: 'logs/access.log', level: 'http' }),
  ],
});

// Middlewares
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  name: "connect.sid",
  secret: "une_phrase_secrete_complexe_et_unique",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 60 * 60 * 1000
  }
}));

// Limiteur de requêtes
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 100,
});
app.use(limiter);

// Logger HTTP avec morgan
app.use(morgan('combined', {
  stream: { write: (msg) => logger.info(msg.trim()) }
}));

// Statique
app.use(express.static(path.join(__dirname, "../public"), { index: false }));

// Redirection vers login si non connecté
app.use((req, res, next) => {
  if (req.path === '/login' || req.path.startsWith('/public') || req.session.user) {
    return next();
  }
  res.redirect('/login');
});

// Routes
app.get("/login", (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, "../public/login.html"));
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  let users;
  try {
    const usersData = fs.readFileSync(path.join(__dirname, "../data/users.json"), "utf-8");
    users = JSON.parse(usersData);
    logger.info("Utilisateurs chargés");
  } catch (error) {
    logger.error("Erreur lecture users.json:", error);
    return res.status(500).send("Erreur serveur");
  }

  const user = users.find(u => u.email === email);
  if (!user) {
    logger.warn(`Utilisateur ${email} non trouvé`);
    return res.status(401).send("Identifiants invalides");
  }

  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    logger.warn(`Mot de passe incorrect pour ${email}`);
    return res.status(401).send("Mot de passe incorrect");
  }

  req.session.user = email;
  logger.info(`Utilisateur ${email} connecté`);
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) logger.error("Erreur de déconnexion:", err);
    res.redirect("/login");
  });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

app.post("/submit", async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Non authentifié" });

  const { nom, email, message, "g-recaptcha-response": recaptchaToken } = req.body;
  if (!recaptchaToken) return res.status(400).json({ error: "reCAPTCHA manquant" });

  const isHuman = await verifyRecaptcha(recaptchaToken);
  if (!isHuman) return res.status(400).json({ error: "Échec reCAPTCHA" });

  const hashedMessage = await bcrypt.hash(message, 10);
  saveMessageToFile(nom, email, hashedMessage);
  logger.info(`Message reçu - ${nom}, ${email}`);

  res.json({ success: "Message reçu !" });
});

app.get("/admin/messages", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Non authentifié" });

  const filePath = path.join(__dirname, "../data/messages.json");
  try {
    const data = fs.readFileSync(filePath, "utf8");
    const messages = JSON.parse(data || "[]");
    res.json(messages);
  } catch (err) {
    logger.error("Erreur lecture messages:", err);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// Utilitaires
async function verifyRecaptcha(token) {
  try {
    const response = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${RECAPTCHA_SECRET}&response=${token}`,
    });
    const data = await response.json();
    return data.success;
  } catch (error) {
    logger.error("Erreur reCAPTCHA:", error);
    return false;
  }
}

function saveMessageToFile(nom, email, hashedMessage) {
  const filePath = path.join(__dirname, "../data/messages.json");
  let messages = [];

  if (fs.existsSync(filePath)) {
    const data = fs.readFileSync(filePath, "utf8");
    messages = JSON.parse(data || "[]");
  }

  messages.push({ nom, email, message: hashedMessage, date: new Date().toISOString() });
  fs.writeFileSync(filePath, JSON.stringify(messages, null, 2), "utf8");
}

// Démarrage serveur HTTPS
const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, "../config/key_no_passphrase.pem")),
  cert: fs.readFileSync(path.join(__dirname, "../config/cert.pem")),
};

const PORT = process.env.PORT || 3000;
https.createServer(sslOptions, app).listen(PORT, () => {
  logger.info(`Serveur HTTPS lancé sur https://localhost:${PORT}`);
});
