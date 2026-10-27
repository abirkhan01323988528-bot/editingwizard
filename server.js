require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcryptjs");
const multer = require("multer");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { google } = require("googleapis");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const UPLOAD_DIR = path.join(ROOT, "uploads");
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database(path.join(DATA_DIR, "editingzone.sqlite"));
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    service TEXT NOT NULL,
    quality TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    price INTEGER NOT NULL,
    brief TEXT NOT NULL,
    files_json TEXT NOT NULL,
    payment_ref TEXT DEFAULT '',
    payment_status TEXT NOT NULL DEFAULT 'Awaiting payment',
    status TEXT NOT NULL DEFAULT 'Awaiting payment',
    drive_links TEXT NOT NULL DEFAULT '[]',
    admin_note TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

const services = {
  photo_basic: { name: "Photo Editing — Basic", base: 100 },
  photo_pro: { name: "Photo Editing — Pro Retouch", base: 250 },
  thumbnail: { name: "YouTube Thumbnail", base: 200 },
  background: { name: "Background Remove", base: 80 },
  reel: { name: "Reels / Shorts Edit", base: 350 },
  gaming: { name: "Gaming Montage", base: 600 },
  youtube: { name: "YouTube Video Edit", base: 800 },
  cinematic: { name: "Cinematic Edit", base: 1000 }
};
const qualities = { standard: 1, high: 1.5, premium: 2 };
const nagadNumber = process.env.NAGAD_NUMBER || "01919610937";

function query(sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows)));
}
function run(sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function(err) {
    err ? reject(err) : resolve({ lastID: this.lastID, changes: this.changes });
  }));
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (err, row) => err ? reject(err) : resolve(row)));
}
function asyncRoute(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }
function requireClient(req, res, next) {
  if (!req.session.userId || req.session.role !== "client") return res.status(401).json({ error: "Please sign in as a client." });
  next();
}
function requireAdmin(req, res, next) {
  if (req.session.role !== "admin") return res.status(401).json({ error: "Admin login required." });
  next();
}
function safeUser(row) { return { id: row.id, email: row.email, username: row.username }; }
function isDriveConfigured() {
  return Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET &&
    process.env.GOOGLE_REFRESH_TOKEN && process.env.DRIVE_FOLDER_ID);
}
function orderForClient(row) {
  return {
    id: row.id, username: row.username, email: row.email, service: row.service,
    quality: row.quality, quantity: row.quantity, price: row.price, brief: row.brief,
    files: JSON.parse(row.files_json || "[]").map(f => ({
      originalName: f.originalName, size: f.size, mimeType: f.mimeType, filename: f.filename
    })),
    paymentRef: row.payment_ref, paymentStatus: row.payment_status, status: row.status,
    driveLinks: JSON.parse(row.drive_links || "[]"), adminNote: row.admin_note,
    createdAt: row.created_at, updatedAt: row.updated_at
  };
}
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).slice(0, 12).replace(/[^.\w-]/g, "");
    cb(null, crypto.randomUUID() + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 150 * 1024 * 1024, files: 5 },
  fileFilter: (_req, file, cb) => {
    const allowed = /^(image\/(jpeg|png|webp|gif)|video\/(mp4|webm|quicktime)|application\/pdf)$/i.test(file.mimetype);
    cb(allowed ? null : new Error("Allowed files: JPG, PNG, WEBP, GIF, MP4, WEBM, MOV, PDF."), allowed);
  }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(ROOT, "public")));

app.get("/api/config", (_req, res) => res.json({
  nagadNumber, services, qualities, driveConfigured: isDriveConfigured()
}));
app.get("/api/me", asyncRoute(async (req, res) => {
  if (req.session.role === "admin") return res.json({ role: "admin", username: process.env.ADMIN_USERNAME || "admin" });
  if (req.session.userId && req.session.role === "client") {
    const user = await get("SELECT * FROM users WHERE id=?", [req.session.userId]);
    if (user) return res.json({ role: "client", user: safeUser(user) });
  }
  res.json({ role: "guest" });
}));

app.post("/api/register", asyncRoute(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
  if (username.length < 2 || username.length > 24) return res.status(400).json({ error: "Username must be 2–24 characters." });
  if (password.length < 8 || password.length > 100) return res.status(400).json({ error: "Site password must be at least 8 characters." });
  const hash = await bcrypt.hash(password, 12);
  try {
    const result = await run("INSERT INTO users(email,username,password_hash,created_at) VALUES(?,?,?,?)",
      [email, username, hash, new Date().toISOString()]);
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "Could not start session." });
      req.session.userId = result.lastID; req.session.role = "client";
      res.json({ ok: true, user: { email, username } });
    });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) return res.status(409).json({ error: "An account with this email already exists. Please sign in." });
    throw e;
  }
}));

app.post("/api/login", asyncRoute(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = await get("SELECT * FROM users WHERE email=?", [email]);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Email or password is incorrect." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start session." });
    req.session.userId = user.id; req.session.role = "client";
    res.json({ ok: true, user: safeUser(user) });
  });
}));

app.post("/api/admin/login", (req, res) => {
  if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) return res.status(500).json({ error: "Set ADMIN_USERNAME and ADMIN_PASSWORD in .env first." });
  if (String(req.body.username || "") !== process.env.ADMIN_USERNAME ||
      String(req.body.password || "") !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Admin username or password is incorrect." });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start session." });
    req.session.role = "admin";
    res.json({ ok: true });
  });
});
app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.post("/api/orders", requireClient, upload.array("files", 5), asyncRoute(async (req, res) => {
  const user = await get("SELECT * FROM users WHERE id=?", [req.session.userId]);
  if (!user) return res.status(401).json({ error: "Please sign in again." });
  const service = services[String(req.body.service || "")];
  const quality = String(req.body.quality || "standard");
  const quantity = Number(req.body.quantity || 1);
  const brief = String(req.body.brief || "").trim();
  const displayName = String(req.body.username || "").trim();
  if (!service) return res.status(400).json({ error: "Choose a valid service." });
  if (!qualities[quality]) return res.status(400).json({ error: "Choose a valid quality." });
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 10) return res.status(400).json({ error: "Quantity must be 1–10." });
  if (brief.length < 20 || brief.length > 2000) return res.status(400).json({ error: "Describe the edit in at least 20 characters (max 2000)." });
  if (displayName !== user.username) return res.status(400).json({ error: "Use the username you registered with." });
  const files = (req.files || []).map(f => ({
    originalName: f.originalname, filename: f.filename, size: f.size,
    mimeType: f.mimetype, localPath: path.join(UPLOAD_DIR, f.filename)
  }));
  const price = Math.round(service.base * qualities[quality] * quantity);
  const id = crypto.randomBytes(5).toString("hex").toUpperCase();
  const now = new Date().toISOString();
  await run(`INSERT INTO orders(id,user_id,username,email,service,quality,quantity,price,brief,files_json,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
    [id, user.id, user.username, user.email, service.name, quality, quantity, price, brief, JSON.stringify(files), now, now]);
  const order = await get("SELECT * FROM orders WHERE id=?", [id]);
  res.json({ ok: true, order: orderForClient(order), nagadNumber });
}));

async function uploadFilesToDrive(files, order) {
  if (!isDriveConfigured() || !files.length) return [];
  const auth = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
  auth.setCredentials({ refresh_token: process.env.GOOGLE_REFRESH_TOKEN });
  const drive = google.drive({ version: "v3", auth });
  const links = [];
  for (const f of files) {
    const result = await drive.files.create({
      requestBody: { name: `EditingZone-${order.id}-${path.basename(f.originalName)}`, parents: [process.env.DRIVE_FOLDER_ID] },
      media: { mimeType: f.mimeType, body: fs.createReadStream(f.localPath) },
      fields: "id,name,webViewLink"
    });
    links.push({ name: result.data.name, url: result.data.webViewLink || `https://drive.google.com/file/d/${result.data.id}/view` });
  }
  return links;
}

app.post("/api/orders/:id/payment", requireClient, asyncRoute(async (req, res) => {
  const id = String(req.params.id);
  const order = await get("SELECT * FROM orders WHERE id=? AND user_id=?", [id, req.session.userId]);
  if (!order) return res.status(404).json({ error: "Order not found." });
  const ref = String(req.body.paymentRef || "").trim();
  if (ref.length < 4 || ref.length > 100) return res.status(400).json({ error: "Enter the Nagad transaction reference/code." });
  const now = new Date().toISOString();
  await run("UPDATE orders SET payment_ref=?,payment_status='Payment review',status='Payment review',updated_at=? WHERE id=?", [ref, now, id]);
  let driveMessage = "Files are saved on this website server for now.";
  try {
    const files = JSON.parse(order.files_json || "[]");
    const links = await uploadFilesToDrive(files, order);
    if (links.length) {
      await run("UPDATE orders SET drive_links=?,updated_at=? WHERE id=?", [JSON.stringify(links), now, id]);
      driveMessage = "Files uploaded to your configured Google Drive folder.";
    } else if (!isDriveConfigured()) {
      driveMessage = "Google Drive is not configured yet. Files are saved on this website server.";
    } else {
      driveMessage = "No source files were attached to this order.";
    }
  } catch (err) {
    console.error("Drive upload error:", err.message);
    driveMessage = "Drive upload failed; files remain saved on the website server.";
  }
  const updated = await get("SELECT * FROM orders WHERE id=?", [id]);
  res.json({ ok: true, order: orderForClient(updated), driveMessage });
}));

app.get("/api/orders", requireClient, asyncRoute(async (req, res) => {
  const rows = await query("SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC", [req.session.userId]);
  res.json({ orders: rows.map(orderForClient) });
}));
app.get("/api/admin/orders", requireAdmin, asyncRoute(async (_req, res) => {
  const rows = await query("SELECT * FROM orders ORDER BY created_at DESC");
  res.json({ orders: rows.map(orderForClient) });
}));
app.post("/api/admin/orders/:id/status", requireAdmin, asyncRoute(async (req, res) => {
  const id = String(req.params.id);
  const status = String(req.body.status || "");
  const allowed = ["Payment review", "Payment rejected", "Editing request accepted", "Editing", "Completed"];
  if (!allowed.includes(status)) return res.status(400).json({ error: "Invalid status." });
  const order = await get("SELECT * FROM orders WHERE id=?", [id]);
  if (!order) return res.status(404).json({ error: "Order not found." });
  const paymentStatus = status === "Payment rejected" ? "Rejected" :
    (["Editing request accepted", "Editing", "Completed"].includes(status) ? "Received / verified by admin" : order.payment_status);
  await run("UPDATE orders SET status=?,payment_status=?,updated_at=? WHERE id=?",
    [status, paymentStatus, new Date().toISOString(), id]);
  res.json({ ok: true });
}));
app.get("/api/admin/files/:filename", requireAdmin, (req, res) => {
  const name = path.basename(req.params.filename);
  const filePath = path.join(UPLOAD_DIR, name);
  if (!fs.existsSync(filePath)) return res.status(404).send("File not found");
  res.download(filePath);
});

app.use((err, _req, res, _next) => {
  console.error(err);
  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.message });
  res.status(500).json({ error: err.message || "Server error" });
});

app.listen(PORT, () => console.log(`EditingZone.net running at http://localhost:${PORT}`));
