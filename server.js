require("dotenv").config();
const express = require("express");
const path = require("path");
const crypto = require("crypto");

const PORT            = process.env.PORT            || 3000;
const API_BASE        = process.env.API_BASE        || "";
const API_KEY         = process.env.API_KEY         || "";   // our secret to backend
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || "";

// ── Developer API keys ────────────────────────────────────────────────────────
// Comma-separated list of allowed developer keys in DEV_KEYS env var.
// e.g. DEV_KEYS=dev_abc123,dev_xyz456
// If DEV_KEYS is not set, all /proxy/* routes are open (for your own web UI use).
// Developers must send their key as: X-API-Key: dev_xxx
// IMPORTANT: developers must NEVER put this key in browser JS — server-side only.
const DEV_KEYS = new Set(
  (process.env.DEV_KEYS || "").split(",").map(k => k.trim()).filter(Boolean)
);

// ── Per-key rate limiter ──────────────────────────────────────────────────────
// 60 requests per minute per key. Sliding window.
const rateLimits = new Map(); // key → [timestamps]
const RATE_LIMIT = 60;
const RATE_WINDOW = 60 * 1000;

function checkRateLimit(key) {
  const now = Date.now();
  const window = now - RATE_WINDOW;
  const hits = (rateLimits.get(key) || []).filter(t => t > window);
  hits.push(now);
  rateLimits.set(key, hits);
  return hits.length <= RATE_LIMIT;
}

// ── Per-key usage log ─────────────────────────────────────────────────────────
const usageLog = []; // last 1000 entries
function logUsage(key, method, path, status) {
  usageLog.push({ ts: new Date().toISOString(), key: key || "open", method, path, status });
  if (usageLog.length > 1000) usageLog.shift();
}

// ── Developer key middleware ──────────────────────────────────────────────────
function requireDevKey(req, res, next) {
  if (DEV_KEYS.size === 0) return next(); // no keys configured — open access (own web UI)
  const key = req.headers["x-api-key"];
  if (!key || !DEV_KEYS.has(key)) {
    return res.status(401).json({
      error: "Invalid or missing API key.",
      hint: "Send your key as: X-API-Key: <your_key>  —  Do NOT put this key in browser JS. Add it server-side only.",
    });
  }
  if (!checkRateLimit(key)) {
    return res.status(429).json({
      error: "Rate limit exceeded. Max 60 requests per minute per key.",
      retry_after: 60,
    });
  }
  req.devKey = key;
  next();
}

const app = express();
app.use(express.json({ limit: "50mb" }));

// Serve web UI only — static files come BEFORE dev key check so the UI page loads
app.use(express.static(path.join(__dirname, "public")));

// ── Session store ─────────────────────────────────────────────────────────────
const sessions = new Map();
const SESSION_TTL = 2 * 60 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) if (s.expiresAt < now) sessions.delete(id);
}, 10 * 60 * 1000).unref();

function makeSessionId() { return crypto.randomBytes(24).toString("hex"); }

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

// ── Backend communication ─────────────────────────────────────────────────────
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

async function proxyToBackend(method, backendPath, body) {
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
  const res = await fetch(`${API_BASE}${backendPath}`, opts);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { _raw: text }; }
  return { status: res.status, data };
}

// ── Proxy routes (developer key + session required) ───────────────────────────

app.post("/proxy/images/generate", requireDevKey, requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("POST", "/v1/images/generate", req.body);
    logUsage(req.devKey, "POST", "/proxy/images/generate", status);
    res.status(status).json(data);
  } catch (e) {
    logUsage(req.devKey, "POST", "/proxy/images/generate", 502);
    res.status(502).json({ error: e.message });
  }
});

app.post("/proxy/videos/generate", requireDevKey, requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("POST", "/v1/videos/generate", req.body);
    logUsage(req.devKey, "POST", "/proxy/videos/generate", status);
    res.status(status).json(data);
  } catch (e) {
    logUsage(req.devKey, "POST", "/proxy/videos/generate", 502);
    res.status(502).json({ error: e.message });
  }
});

app.get("/proxy/jobs/:id", requireDevKey, requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("GET", `/v1/jobs/${req.params.id}`);
    logUsage(req.devKey, "GET", "/proxy/jobs/:id", status);
    res.status(status).json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get("/proxy/models", requireDevKey, requireSession, async (req, res) => {
  const type = req.query.type || "image";
  try {
    const res2 = await fetch(`${API_BASE}/v1/models?type=${type}`, {
      headers: INTERNAL_SECRET ? { "X-Internal-Secret": INTERNAL_SECRET } : {},
      signal: AbortSignal.timeout(15000),
    });
    const data = await res2.json();
    logUsage(req.devKey, "GET", "/proxy/models", res2.status);
    res.status(res2.status).json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.post("/proxy/upload", requireDevKey, requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("POST", "/v1/upload", req.body);
    logUsage(req.devKey, "POST", "/proxy/upload", status);
    res.status(status).json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get("/proxy/accounts", requireDevKey, requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("GET", "/v1/accounts");
    logUsage(req.devKey, "GET", "/proxy/accounts", status);
    res.status(status).json(data);
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// ── Health & usage (public) ───────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    sessions: sessions.size,
    uptime: Math.floor(process.uptime()),
    keys_configured: DEV_KEYS.size,
  });
});

app.get("/usage", (req, res) => {
  // Internal usage log — only accessible with master API_KEY
  const key = req.headers["x-api-key"];
  if (API_KEY && key !== API_KEY) return res.status(401).json({ error: "Forbidden." });
  const limit = Math.min(Number(req.query.limit) || 100, 1000);
  res.json(usageLog.slice(-limit));
});

// ── Serve SPA ─────────────────────────────────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`[bridgegate-frontend] running on port ${PORT}`);
  if (!API_KEY) console.warn("[warn] API_KEY not set — backend calls will fail");
  if (!API_BASE) console.warn("[warn] API_BASE not set");
  if (DEV_KEYS.size === 0) console.warn("[warn] DEV_KEYS not set — /proxy/* routes are open");
  else console.log(`[auth] ${DEV_KEYS.size} developer key(s) configured`);
});
