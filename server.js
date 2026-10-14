require("dotenv").config();
const express = require("express");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const API_BASE        = process.env.API_BASE        || "";
const API_KEY         = process.env.API_KEY         || "";
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || "";

const app = express();
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ── Session store ─────────────────────────────────────────────────────────────
// Browser gets a random session ID (cookie-like header) valid for 2 hours.
// Server maps session → a short-lived backend JWT it fetches once per session.
// Browser never sees the API key or the backend JWT.
const sessions = new Map(); // sessionId → { backendToken, fetchedAt, expiresAt }
const SESSION_TTL = 2 * 60 * 60 * 1000; // 2 hours
const BACKEND_TOKEN_TTL = 55 * 1000;    // fetch fresh backend JWT every 55s (JWT is 60s)

setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) if (s.expiresAt < now) sessions.delete(id);
}, 10 * 60 * 1000).unref();

function makeSessionId() { return crypto.randomBytes(24).toString("hex"); }

// Fetch a fresh single-use JWT from the backend using our secret API key
async function fetchBackendToken() {
  const res = await fetch(`${API_BASE}/v1/auth/token`, {
    headers: {
      "X-API-Key": API_KEY,
      ...(INTERNAL_SECRET ? { "X-Internal-Secret": INTERNAL_SECRET } : {}),
    },
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`Backend token fetch failed: ${res.status}`);
  const d = await res.json();
  return d.token;
}

// Proxy a request to the backend — always fetches a fresh JWT server-side
async function proxyToBackend(method, path, body) {
  const token = await fetchBackendToken();
  const opts = {
    method,
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
      ...(INTERNAL_SECRET ? { "X-Internal-Secret": INTERNAL_SECRET } : {}),
    },
    signal: AbortSignal.timeout(35000),
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${API_BASE}${path}`, opts);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { _raw: text }; }
  return { status: res.status, data };
}

// ── Session middleware ─────────────────────────────────────────────────────────
// Every browser request carries X-Session-Id. Server issues one on first visit.
function getOrCreateSession(req) {
  const id = req.headers["x-session-id"];
  if (id && sessions.has(id)) {
    const s = sessions.get(id);
    if (s.expiresAt > Date.now()) return id;
    sessions.delete(id);
  }
  const newId = makeSessionId();
  sessions.set(newId, { expiresAt: Date.now() + SESSION_TTL });
  return newId;
}

function requireSession(req, res, next) {
  req.sessionId = getOrCreateSession(req);
  res.setHeader("X-Session-Id", req.sessionId);
  next();
}

// ── Proxy routes ──────────────────────────────────────────────────────────────
// These routes are called by the browser's JS. They proxy server-side.
// The browser sees only session IDs — never the API key or backend JWT.

app.post("/proxy/images/generate", requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("POST", "/v1/images/generate", req.body);
    res.status(status).json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.post("/proxy/videos/generate", requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("POST", "/v1/videos/generate", req.body);
    res.status(status).json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get("/proxy/jobs/:id", requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("GET", `/v1/jobs/${req.params.id}`);
    res.status(status).json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get("/proxy/models", requireSession, async (req, res) => {
  const type = req.query.type || "image";
  try {
    // /v1/models is public on the backend (no JWT needed), call directly
    const res2 = await fetch(`${API_BASE}/v1/models?type=${type}`, {
      headers: INTERNAL_SECRET ? { "X-Internal-Secret": INTERNAL_SECRET } : {},
      signal: AbortSignal.timeout(15000),
    });
    const data = await res2.json();
    res.status(res2.status).json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.post("/proxy/upload", requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("POST", "/v1/upload", req.body);
    res.status(status).json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get("/proxy/accounts", requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("GET", "/v1/accounts");
    res.status(status).json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", sessions: sessions.size, uptime: Math.floor(process.uptime()) });
});

// ── Serve SPA for all other routes ────────────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`[bridgegate-frontend] running on port ${PORT}`);
  if (!API_KEY) console.warn("[warn] API_KEY not set — backend calls will fail");
  if (!API_BASE) console.warn("[warn] API_BASE not set");
});
