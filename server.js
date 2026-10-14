require("dotenv").config();
const express      = require("express");
const path         = require("path");
const crypto       = require("crypto");
const cookieParser = require("cookie-parser");
const OTPAuth      = require("otpauth");

const PORT            = process.env.PORT            || 3000;
const API_BASE        = process.env.API_BASE        || "";
const API_KEY         = process.env.API_KEY         || "";
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || "";
const RENDER_API_KEY  = process.env.RENDER_API_KEY  || "";
const RENDER_SVC_ID   = process.env.RENDER_SVC_ID   || "";  // backend service id for sync

// ── Developer API keys ────────────────────────────────────────────────────────
let devKeys = new Set(
  (process.env.DEV_KEYS || "").split(",").map(k => k.trim()).filter(Boolean)
);

// ── Per-key rate limiter ──────────────────────────────────────────────────────
const rateLimits = new Map();
const RATE_LIMIT  = 60;
const RATE_WINDOW = 60 * 1000;

function checkRateLimit(key) {
  const now    = Date.now();
  const window = now - RATE_WINDOW;
  const hits   = (rateLimits.get(key) || []).filter(t => t > window);
  hits.push(now);
  rateLimits.set(key, hits);
  return hits.length <= RATE_LIMIT;
}

// ── Per-key usage log ─────────────────────────────────────────────────────────
const usageLog = [];
function logUsage(key, method, p, status) {
  usageLog.push({ ts: new Date().toISOString(), key: key || "open", method, path: p, status });
  if (usageLog.length > 1000) usageLog.shift();
}

// ── Developer key middleware ──────────────────────────────────────────────────
function requireDevKey(req, res, next) {
  if (devKeys.size === 0) return next();
  const key = req.headers["x-api-key"];
  if (!key || !devKeys.has(key)) {
    return res.status(401).json({
      error: "Invalid or missing API key.",
      hint:  "Send your key as: X-API-Key: <your_key>  —  Server-side only, never in browser JS.",
    });
  }
  if (!checkRateLimit(key)) {
    return res.status(429).json({ error: "Rate limit exceeded (60/min per key).", retry_after: 60 });
  }
  req.devKey = key;
  next();
}

// ── TOTP admin auth ───────────────────────────────────────────────────────────
let TOTP_INSTANCE  = null;
let TOTP_SECRET_B32 = process.env.TOTP_SECRET || "";

function setupTOTP() {
  if (TOTP_SECRET_B32) {
    try {
      TOTP_INSTANCE = new OTPAuth.TOTP({
        issuer: "BridgegateAdmin", label: "Bridgegate Admin",
        secret: OTPAuth.Secret.fromBase32(TOTP_SECRET_B32), digits: 6, period: 30,
      });
      console.log("[TOTP] Admin 2FA ready.");
    } catch (e) { console.error("[TOTP] Invalid TOTP_SECRET:", e.message); }
  } else {
    const secret = new OTPAuth.Secret({ size: 20 });
    TOTP_SECRET_B32 = secret.base32;
    TOTP_INSTANCE   = new OTPAuth.TOTP({
      issuer: "BridgegateAdmin", label: "Bridgegate Admin",
      secret, digits: 6, period: 30,
    });
    console.warn("[TOTP] Auto-generated. Set TOTP_SECRET=" + TOTP_SECRET_B32 + " in Render env to persist.");
    console.log("[TOTP] URI:", TOTP_INSTANCE.toString());
  }
}
setupTOTP();

const ADMIN_TTL = 7 * 24 * 3600 * 1000; // 7 days

// Stateless signed session — survives server restarts
// Cookie value: "<expiry_ms>.<hmac_hex>"
function _sessionSecret() {
  // Use TOTP secret as signing key (always present after setupTOTP)
  return crypto.createHash("sha256").update("admin-session:" + TOTP_SECRET_B32).digest();
}
function createAdminSession() {
  const exp = String(Date.now() + ADMIN_TTL);
  const mac = crypto.createHmac("sha256", _sessionSecret()).update(exp).digest("hex");
  return exp + "." + mac;
}
function isAdminSession(tok) {
  if (!tok) return false;
  const dot = tok.lastIndexOf(".");
  if (dot < 0) return false;
  const exp = tok.slice(0, dot);
  const mac = tok.slice(dot + 1);
  const expected = crypto.createHmac("sha256", _sessionSecret()).update(exp).digest("hex");
  // Constant-time compare
  try {
    if (!crypto.timingSafeEqual(Buffer.from(mac, "hex"), Buffer.from(expected, "hex"))) return false;
  } catch { return false; }
  return Date.now() < Number(exp);
}
function verifyTOTP(code) {
  if (!TOTP_INSTANCE) return false;
  return TOTP_INSTANCE.validate({ token: String(code).replace(/\s/g, ""), window: 1 }) !== null;
}
function adminAuth(req, res, next) {
  if (isAdminSession(req.cookies?.admin_tok)) return next();
  if (req.method !== "GET")
    return res.status(401).json({ ok: false, error: "Session expired — log in at /admin/login" });
  res.redirect("/admin/login?next=" + encodeURIComponent(req.path));
}

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ── Session store (for proxy) ─────────────────────────────────────────────────
const sessions   = new Map();
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
  const res  = await fetch(`${API_BASE}${backendPath}`, opts);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { _raw: text }; }
  return { status: res.status, data };
}

// Admin-only backend call (no JWT — goes direct to backend admin routes)
async function backendAdmin(method, adminPath, body) {
  const opts = {
    method,
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": API_KEY,
      ...(INTERNAL_SECRET ? { "X-Internal-Secret": INTERNAL_SECRET } : {}),
    },
    signal: AbortSignal.timeout(20000),
  };
  if (body) opts.body = JSON.stringify(body);
  const res  = await fetch(`${API_BASE}${adminPath}`, opts);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { _raw: text }; }
  return { status: res.status, data };
}

// ── Proxy routes ──────────────────────────────────────────────────────────────
app.post("/proxy/images/generate", requireDevKey, requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("POST", "/v1/images/generate", req.body);
    logUsage(req.devKey, "POST", "/proxy/images/generate", status);
    res.status(status).json(data);
  } catch (e) { logUsage(req.devKey, "POST", "/proxy/images/generate", 502); res.status(502).json({ error: e.message }); }
});

app.post("/proxy/videos/generate", requireDevKey, requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("POST", "/v1/videos/generate", req.body);
    logUsage(req.devKey, "POST", "/proxy/videos/generate", status);
    res.status(status).json(data);
  } catch (e) { logUsage(req.devKey, "POST", "/proxy/videos/generate", 502); res.status(502).json({ error: e.message }); }
});

app.get("/proxy/jobs/:id", requireDevKey, requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("GET", `/v1/jobs/${req.params.id}`);
    logUsage(req.devKey, "GET", "/proxy/jobs/:id", status);
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

app.get("/proxy/models", requireDevKey, requireSession, async (req, res) => {
  const type = req.query.type || "image";
  try {
    const r2 = await fetch(`${API_BASE}/v1/models?type=${type}`, {
      headers: INTERNAL_SECRET ? { "X-Internal-Secret": INTERNAL_SECRET } : {},
      signal: AbortSignal.timeout(15000),
    });
    const data = await r2.json();
    logUsage(req.devKey, "GET", "/proxy/models", r2.status);
    res.status(r2.status).json(data);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

app.post("/proxy/upload", requireDevKey, requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("POST", "/v1/upload", req.body);
    logUsage(req.devKey, "POST", "/proxy/upload", status);
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

app.get("/proxy/accounts", requireDevKey, requireSession, async (req, res) => {
  try {
    const { status, data } = await proxyToBackend("GET", "/v1/accounts");
    logUsage(req.devKey, "GET", "/proxy/accounts", status);
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// ── Health & usage ────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", sessions: sessions.size, uptime: Math.floor(process.uptime()), keys_configured: devKeys.size });
});

app.get("/usage", (req, res) => {
  const key = req.headers["x-api-key"];
  if (API_KEY && key !== API_KEY) return res.status(401).json({ error: "Forbidden." });
  const limit = Math.min(Number(req.query.limit) || 100, 1000);
  res.json(usageLog.slice(-limit));
});

// ── Admin login ───────────────────────────────────────────────────────────────
app.get("/admin/login", (req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  const next = req.query.next || "/admin";
  res.send(`<!DOCTYPE html><html><head><title>Bridgegate Admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#0a0a0c;color:#f0f0f4;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{background:#111115;border:1px solid #222228;border-radius:16px;padding:36px;width:340px}
h2{font-size:20px;font-weight:700;margin-bottom:6px}
p{font-size:13px;color:#6b6b78;margin-bottom:24px}
input{width:100%;background:#17171d;border:1px solid #28282f;color:#f0f0f4;border-radius:10px;padding:12px 14px;font-size:15px;margin-bottom:14px;outline:none;letter-spacing:4px}
input:focus{border-color:#7c6cff}
button{width:100%;padding:13px;border:none;border-radius:10px;background:linear-gradient(135deg,#7c6cff,#9d8fff);color:#fff;font-size:15px;font-weight:600;cursor:pointer}
.err{color:#ff6b6b;font-size:13px;margin-bottom:14px;padding:10px;background:#ff6b6b18;border-radius:8px}
</style></head><body>
<div class="box">
  <h2>Bridgegate Admin</h2>
  <p>Enter your 6-digit authenticator code</p>
  <form method="POST" action="/admin/login">
    <input type="hidden" name="next" value="${next}">
    ${req.query.err ? '<div class="err">Invalid code — try again</div>' : ''}
    <input name="totp" placeholder="000000" autofocus autocomplete="off" maxlength="6" inputmode="numeric">
    <button type="submit">Login</button>
  </form>
</div></body></html>`);
});

app.post("/admin/login", (req, res) => {
  const { totp, next } = req.body;
  if (!verifyTOTP(totp)) return res.redirect("/admin/login?err=1");
  const tok = createAdminSession();
  res.cookie("admin_tok", tok, { httpOnly: true, maxAge: ADMIN_TTL, sameSite: "lax" });
  res.redirect(next || "/admin");
});

app.post("/admin/logout", (req, res) => {
  res.clearCookie("admin_tok");
  res.json({ ok: true });
});

// ── Admin API routes (proxy through to backend admin) ─────────────────────────
app.get("/admin/api/accounts", adminAuth, async (req, res) => {
  try {
    const { status, data } = await backendAdmin("GET", "/admin/accounts/export");
    // Also get live credits from /v1/accounts (uses JWT)
    let live = [];
    try {
      const r2 = await proxyToBackend("GET", "/v1/accounts");
      live = Array.isArray(r2.data) ? r2.data : [];
    } catch {}
    // Merge live credits into export data
    const accounts = (data.accounts || []).map(a => {
      const l = live.find(l => l.email === a.email);
      return { ...a,
        credits:          l?.credits          ?? null,
        credits_limit:    l?.credits_limit    ?? null,
        credits_used:     l?.credits_used     ?? null,
        plan:             l?.plan             ?? null,
        status:           l?.status           ?? null,
        token_expires_at: l?.token_expires_at ?? null,
      };
    });
    res.status(status).json({ accounts });
  } catch (e) { res.status(502).json({ ok: false, error: e.message }); }
});

app.post("/admin/api/accounts/add", adminAuth, async (req, res) => {
  try {
    const { status, data } = await backendAdmin("POST", "/admin/accounts/add", req.body);
    if (data.ok) autoSync();
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ ok: false, error: e.message }); }
});

app.post("/admin/api/accounts/remove", adminAuth, async (req, res) => {
  try {
    const { status, data } = await backendAdmin("POST", "/admin/accounts/remove", req.body);
    if (data.ok) autoSync();
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ ok: false, error: e.message }); }
});

app.post("/admin/api/accounts/toggle", adminAuth, async (req, res) => {
  try {
    const { status, data } = await backendAdmin("POST", "/admin/accounts/toggle", req.body);
    if (data.ok) autoSync();
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ ok: false, error: e.message }); }
});

// Per-account live credit check (or all if no email given)
app.post("/admin/api/accounts/check", adminAuth, async (req, res) => {
  try {
    const { email } = req.body || {};
    const r2 = await proxyToBackend("GET", "/v1/accounts");
    const all = Array.isArray(r2.data) ? r2.data : [];
    if (email) {
      const entry = all.find(a => a.email === email);
      if (!entry) return res.json({ ok: false, error: "Account not found" });
      return res.json({ ok: true, account: entry });
    }
    res.json({ ok: true, accounts: all });
  } catch (e) { res.status(502).json({ ok: false, error: e.message }); }
});

app.get("/admin/api/export", adminAuth, async (req, res) => {
  try {
    const { status, data } = await backendAdmin("GET", "/admin/accounts/export");
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ ok: false, error: e.message }); }
});

app.get("/admin/api/logs", adminAuth, async (req, res) => {
  try {
    const r = await fetch(`${API_BASE}/logs?limit=80`, {
      headers: INTERNAL_SECRET ? { "X-Internal-Secret": INTERNAL_SECRET } : {},
      signal: AbortSignal.timeout(10000),
    });
    const data = await r.json();
    res.json(data);
  } catch (e) { res.json([]); }
});

// Developer key management (frontend-only — no backend involvement)
app.get("/admin/api/devkeys", adminAuth, (req, res) => {
  res.json({ keys: [...devKeys] });
});

app.post("/admin/api/devkeys/add", adminAuth, (req, res) => {
  const { key } = req.body;
  if (!key || key.length < 8) return res.json({ ok: false, error: "Key too short (min 8 chars)" });
  devKeys.add(key.trim());
  res.json({ ok: true, keys: [...devKeys] });
});

app.post("/admin/api/devkeys/remove", adminAuth, (req, res) => {
  const { key } = req.body;
  devKeys.delete(key);
  res.json({ ok: true, keys: [...devKeys] });
});

app.post("/admin/api/devkeys/generate", adminAuth, (req, res) => {
  const key = "dev_" + crypto.randomBytes(16).toString("hex");
  devKeys.add(key);
  res.json({ ok: true, key, keys: [...devKeys] });
});

// Auto-sync helper — called after any account mutation
async function autoSync() {
  if (!RENDER_API_KEY || !RENDER_SVC_ID) return;
  try {
    const { data: exportData } = await backendAdmin("GET", "/admin/accounts/export");
    const accountsJson = JSON.stringify(exportData.accounts || []);
    const listRes = await fetch(`https://api.render.com/v1/services/${RENDER_SVC_ID}/env-vars`, {
      headers: { "Authorization": `Bearer ${RENDER_API_KEY}` },
    });
    const existing = await listRes.json();
    const envVars = (existing || []).map(e => e.envVar || e).filter(e => e.key && e.key !== "ACCOUNTS_JSON");
    envVars.push({ key: "ACCOUNTS_JSON", value: accountsJson });
    await fetch(`https://api.render.com/v1/services/${RENDER_SVC_ID}/env-vars`, {
      method: "PUT",
      headers: { "Authorization": `Bearer ${RENDER_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(envVars),
    });
  } catch (e) { console.error("[autoSync] failed:", e.message); }
}

// Sync ACCOUNTS_JSON to Render env var
app.post("/admin/api/sync", adminAuth, async (req, res) => {
  if (!RENDER_API_KEY || !RENDER_SVC_ID) {
    return res.json({ ok: false, error: "RENDER_API_KEY or RENDER_SVC_ID not configured on this service" });
  }
  try {
    const { data: exportData } = await backendAdmin("GET", "/admin/accounts/export");
    const accountsJson = JSON.stringify(exportData.accounts || []);

    // Get existing env vars
    const listRes = await fetch(`https://api.render.com/v1/services/${RENDER_SVC_ID}/env-vars`, {
      headers: { "Authorization": `Bearer ${RENDER_API_KEY}` },
    });
    const existing = await listRes.json();
    const envVars  = (existing || []).map(e => e.envVar || e).filter(e => e.key && e.key !== "ACCOUNTS_JSON");
    envVars.push({ key: "ACCOUNTS_JSON", value: accountsJson });

    const putRes = await fetch(`https://api.render.com/v1/services/${RENDER_SVC_ID}/env-vars`, {
      method: "PUT",
      headers: { "Authorization": `Bearer ${RENDER_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(envVars),
    });
    if (!putRes.ok) throw new Error(`Render API error: ${putRes.status}`);
    res.json({ ok: true, accounts_saved: (exportData.accounts || []).length });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

// ── Admin panel HTML ──────────────────────────────────────────────────────────
app.get("/admin", adminAuth, (req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.send(`<!DOCTYPE html>
<html><head>
<title>Bridgegate Admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0a0c;--surface:#111115;--border:#222228;--border2:#2a2a32;--text:#f0f0f4;--muted:#6b6b78;--accent:#7c6cff;--green:#3dd68c;--red:#ff6b6b;--yellow:#ffb23e}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
header{display:flex;align-items:center;justify-content:space-between;padding:18px 28px;border-bottom:1px solid var(--border);background:var(--surface)}
header h1{font-size:17px;font-weight:700}
header .actions{display:flex;gap:10px;align-items:center}
.main{padding:24px 28px;max-width:1200px}
h2{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin:28px 0 14px}
h2:first-child{margin-top:0}

/* Stats bar */
.stats{display:flex;gap:14px;margin-bottom:28px;flex-wrap:wrap}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 20px;min-width:110px}
.stat-val{font-size:26px;font-weight:700}
.stat-val.green{color:var(--green)}.stat-val.yellow{color:var(--yellow)}.stat-val.blue{color:#63b3ff}
.stat-label{font-size:11px;color:var(--muted);margin-top:2px;text-transform:uppercase;letter-spacing:.5px}

/* Account cards */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:14px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px;position:relative;transition:border .15s}
.card:hover{border-color:var(--border2)}
.card-email{font-size:14px;font-weight:600;margin-bottom:6px;word-break:break-all}
.card-meta{font-size:12px;color:var(--muted);margin-bottom:12px}
.card-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:20px;font-size:11px;font-weight:600}
.badge.active{background:#3dd68c22;color:var(--green)}.badge.inactive{background:#ff6b6b22;color:var(--red)}
.badge::before{content:'';display:inline-block;width:6px;height:6px;border-radius:50%;background:currentColor}
.card-credits{font-size:13px;color:var(--muted)}.card-credits span{color:var(--text);font-weight:600}
.card-used{font-size:11px;color:var(--muted);margin-top:4px}
.card-btns{display:flex;gap:8px;margin-top:14px}
button,.btn{padding:8px 14px;border:none;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;background:#7c6cff22;color:var(--accent);border:1px solid #7c6cff33;transition:background .15s}
button:hover,.btn:hover{background:#7c6cff44}
.btn-danger{background:#ff6b6b18;color:var(--red);border-color:#ff6b6b33}
.btn-danger:hover{background:#ff6b6b30}
.btn-green{background:#3dd68c18;color:var(--green);border-color:#3dd68c33}
.btn-solid{background:var(--accent);color:#fff;border-color:transparent}
.btn-solid:hover{background:#9d8fff}
.btn-sm{padding:6px 11px;font-size:11px}

/* Forms */
.form-row{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
input[type=text],input[type=password],input[type=email]{flex:1;min-width:180px;background:#17171d;border:1px solid var(--border2);color:var(--text);border-radius:8px;padding:10px 12px;font-size:13px;outline:none}
input:focus{border-color:var(--accent)}

/* Dev keys table */
.key-row{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--border);font-size:13px}
.key-row:last-child{border-bottom:none}
.key-val{flex:1;font-family:monospace;font-size:12px;background:#17171d;border:1px solid var(--border2);border-radius:6px;padding:6px 10px;color:#9d8fff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* Logs */
.log-box{background:#0d0d10;border:1px solid var(--border);border-radius:10px;padding:14px;font-family:monospace;font-size:12px;color:var(--muted);max-height:280px;overflow-y:auto}
.log-entry{padding:2px 0}.log-ts{color:#3a3a48}.log-err{color:var(--red)}.log-warn{color:var(--yellow)}.log-ok{color:var(--green)}

/* Toast */
#toast{position:fixed;bottom:24px;right:24px;background:#222228;border:1px solid #333340;border-radius:10px;padding:12px 18px;font-size:13px;display:none;z-index:100;max-width:320px}
#toast.show{display:block}#toast.ok{border-color:#3dd68c44;color:var(--green)}#toast.err{border-color:#ff6b6b44;color:var(--red)}

.divider{border:none;border-top:1px solid var(--border);margin:24px 0}
</style>
</head><body>

<header>
  <h1>Bridgegate Admin</h1>
  <div class="actions">
    <button class="btn btn-sm" id="refresh-btn" onclick="refreshAllAccounts()">Refresh Accounts</button>
    <button class="btn btn-green btn-sm" onclick="syncToRender()" id="sync-btn">Sync to Render</button>
    <button class="btn btn-sm" onclick="location.href='/usage'">Usage Log</button>
    <button class="btn btn-danger btn-sm" onclick="doLogout()">Logout</button>
  </div>
</header>

<div class="main">

<!-- Stats -->
<div class="stats" id="stats">
  <div class="stat"><div class="stat-val green" id="s-active">—</div><div class="stat-label">Active Accounts</div></div>
  <div class="stat"><div class="stat-val blue"  id="s-total">—</div><div class="stat-label">Total Accounts</div></div>
  <div class="stat"><div class="stat-val yellow" id="s-keys">—</div><div class="stat-label">Dev Keys</div></div>
  <div class="stat"><div class="stat-val"       id="s-sess">—</div><div class="stat-label">Active Sessions</div></div>
</div>

<!-- Accounts -->
<h2>Accounts</h2>
<div class="cards" id="cards"><em style="color:var(--muted)">Loading…</em></div>

<hr class="divider">

<!-- Add account -->
<h2>Add Account</h2>
<div class="form-row">
  <input type="email" id="add-email" placeholder="email@example.com">
  <input type="password" id="add-pass" placeholder="Password (used once, never stored)">
  <button class="btn btn-solid" onclick="addAccount()">Add Account</button>
</div>
<div id="add-status" style="font-size:13px;min-height:18px"></div>

<hr class="divider">

<!-- Export -->
<h2>Export ACCOUNTS_JSON</h2>
<p style="font-size:13px;color:var(--muted);margin-bottom:12px">Copy this value and paste it into the backend Render service's ACCOUNTS_JSON env var to persist accounts across restarts. Or click "Sync to Render" above (requires RENDER_API_KEY + RENDER_SVC_ID configured).</p>
<div class="form-row">
  <input type="text" id="export-json" readonly style="font-family:monospace;font-size:11px">
  <button class="btn btn-sm" onclick="copyExport()">Copy</button>
</div>

<hr class="divider">

<!-- Developer keys -->
<h2>Developer API Keys</h2>
<p style="font-size:13px;color:var(--muted);margin-bottom:12px">Developers send their key as <code style="background:#1a1a22;padding:2px 6px;border-radius:4px;font-size:11px">X-API-Key: &lt;key&gt;</code> on every /proxy/* request — from their server only, never browser JS.</p>
<div id="key-list" style="margin-bottom:14px"></div>
<div class="form-row">
  <input type="text" id="new-key" placeholder="Enter key or leave blank to auto-generate">
  <button class="btn btn-solid" onclick="addKey()">Add Key</button>
  <button class="btn" onclick="genKey()">Generate</button>
</div>

<hr class="divider">

<!-- Logs -->
<h2>Backend Logs</h2>
<div class="log-box" id="log-box"><em>Loading…</em></div>

</div><!-- /main -->

<div id="toast"></div>

<script>
function toast(msg, type='ok') {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = 'show ' + type;
  setTimeout(() => t.className = '', 3000);
}

async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  return r.json();
}

// ── Accounts ────────────────────────────────────────────────────────────────
async function loadAccounts() {
  const d = await api('GET', '/admin/api/accounts');
  const list = d.accounts || [];
  const active = list.filter(a => a.active !== false).length;
  document.getElementById('s-active').textContent = active;
  document.getElementById('s-total').textContent  = list.length;

  const cards = document.getElementById('cards');
  if (!list.length) { cards.innerHTML = '<em style="color:var(--muted)">No accounts yet — add one below</em>'; return; }

  cards.innerHTML = list.map(a => {
    const isActive = a.active !== false;
    const exp = a.token_expires_at ? 'Token expires ' + new Date(a.token_expires_at).toLocaleTimeString() : 'Token not refreshed yet';
    return \`<div class="card" id="card-\${btoa(a.email).replace(/[^a-z0-9]/gi,'')}">
      <div class="card-row">
        <span class="badge \${isActive ? 'active' : 'inactive'}">\${isActive ? 'active' : 'inactive'}</span>
      </div>
      <div class="card-email">\${a.email}</div>
      <div class="card-meta">\${exp}</div>
      <div class="card-credits">Plan: <span>\${a.plan ?? '—'}</span> &nbsp;·&nbsp; Status: <span>\${a.status ?? '—'}</span></div>
      <div class="card-credits">Remaining: <span>\${a.credits ?? '—'}</span> &nbsp;/&nbsp; Limit: <span>\${a.credits_limit ?? '—'}</span></div>
      <div class="card-credits" style="font-size:11px;color:var(--muted)">Used: \${a.credits_used ?? '—'}</div>
      <div class="card-btns">
        <button class="btn btn-sm" onclick="checkAccount('\${a.email}')">Check</button>
        <button class="btn btn-sm \${isActive ? 'btn-danger' : 'btn-green'}" onclick="toggleAccount('\${a.email}',\${isActive})">
          \${isActive ? 'Disable' : 'Enable'}
        </button>
        <button class="btn btn-danger btn-sm" onclick="removeAccount('\${a.email}')">Remove</button>
      </div>
    </div>\`;
  }).join('');
}

async function addAccount() {
  const email = document.getElementById('add-email').value.trim();
  const pass  = document.getElementById('add-pass').value;
  const st    = document.getElementById('add-status');
  if (!email || !pass) { st.textContent = 'Fill in email and password.'; st.style.color = 'var(--red)'; return; }
  st.textContent = 'Adding…'; st.style.color = 'var(--muted)';
  const r = await api('POST', '/admin/api/accounts/add', { email, password: pass });
  if (r.ok) {
    st.textContent = ''; document.getElementById('add-email').value = ''; document.getElementById('add-pass').value = '';
    toast('Added: ' + email);
    loadAccounts(); loadExport();
  } else { st.textContent = 'Error: ' + r.error; st.style.color = 'var(--red)'; }
}

async function removeAccount(email) {
  if (!confirm('Remove ' + email + '?')) return;
  const r = await api('POST', '/admin/api/accounts/remove', { email });
  if (r.ok) { toast('Removed: ' + email); loadAccounts(); loadExport(); }
  else toast('Error: ' + r.error, 'err');
}

async function toggleAccount(email, isActive) {
  const r = await api('POST', '/admin/api/accounts/toggle', { email, active: !isActive });
  if (r.ok) { toast((isActive ? 'Disabled' : 'Enabled') + ': ' + email); loadAccounts(); }
  else { toast('Toggle not supported by backend (add POST /admin/accounts/toggle)', 'err'); }
}

async function checkAccount(email) {
  toast('Checking ' + email + '…');
  const r = await api('POST', '/admin/api/accounts/check', { email });
  if (r.ok && r.account) {
    const a = r.account;
    if (a.error) { toast(email + ' — ERROR: ' + a.error, 'err'); return; }
    const remaining = a.credits ?? '?';
    const limit     = a.credits_limit ?? '?';
    const used      = a.credits_used ?? '?';
    const plan      = a.plan ?? '?';
    const status    = a.status ?? '?';
    toast(\`\${plan} | \${status} | Remaining=\${remaining} Limit=\${limit} Used=\${used}\`, 'ok');
    loadAccounts();
  } else {
    toast('Check failed: ' + (r.error || 'unknown'), 'err');
  }
}

async function refreshAllAccounts() {
  const btn = document.getElementById('refresh-btn');
  btn.textContent = 'Refreshing…'; btn.disabled = true;
  const r = await api('POST', '/admin/api/accounts/check', {});
  btn.textContent = 'Refresh Accounts'; btn.disabled = false;
  if (r.ok) { toast('Refreshed ' + (r.accounts || []).length + ' accounts'); loadAccounts(); }
  else toast('Refresh failed: ' + r.error, 'err');
}

// ── Export ──────────────────────────────────────────────────────────────────
async function loadExport() {
  const d = await api('GET', '/admin/api/export');
  document.getElementById('export-json').value = JSON.stringify(d.accounts || []);
}

function copyExport() {
  const v = document.getElementById('export-json').value;
  navigator.clipboard.writeText(v).then(() => toast('Copied ACCOUNTS_JSON to clipboard'));
}

// ── Sync to Render ──────────────────────────────────────────────────────────
async function syncToRender() {
  const btn = document.getElementById('sync-btn');
  btn.textContent = 'Syncing…'; btn.disabled = true;
  const r = await api('POST', '/admin/api/sync');
  btn.textContent = 'Sync to Render'; btn.disabled = false;
  if (r.ok) toast('Synced ' + r.accounts_saved + ' accounts to Render env var');
  else toast('Sync failed: ' + r.error, 'err');
}

// ── Developer keys ──────────────────────────────────────────────────────────
async function loadKeys() {
  const d = await api('GET', '/admin/api/devkeys');
  const keys = d.keys || [];
  document.getElementById('s-keys').textContent = keys.length;
  const el = document.getElementById('key-list');
  if (!keys.length) { el.innerHTML = '<em style="color:var(--muted);font-size:13px">No keys configured — all /proxy/* routes are open</em>'; return; }
  el.innerHTML = keys.map(k => \`
    <div class="key-row">
      <div class="key-val">\${k}</div>
      <button class="btn btn-sm" onclick="copyKey('\${k}')">Copy</button>
      <button class="btn btn-danger btn-sm" onclick="delKey('\${k}')">Remove</button>
    </div>
  \`).join('');
}

function copyKey(k) {
  navigator.clipboard.writeText(k).then(() => toast('Copied key'));
}

async function addKey() {
  const key = document.getElementById('new-key').value.trim();
  if (!key) { genKey(); return; }
  const r = await api('POST', '/admin/api/devkeys/add', { key });
  if (r.ok) { document.getElementById('new-key').value = ''; toast('Key added'); loadKeys(); }
  else toast('Error: ' + r.error, 'err');
}

async function genKey() {
  const r = await api('POST', '/admin/api/devkeys/generate');
  if (r.ok) { toast('Generated: ' + r.key); loadKeys(); }
}

async function delKey(key) {
  if (!confirm('Remove key ' + key + '?')) return;
  const r = await api('POST', '/admin/api/devkeys/remove', { key });
  if (r.ok) { toast('Key removed'); loadKeys(); }
}

// ── Logs ────────────────────────────────────────────────────────────────────
async function loadLogs() {
  const logs = await api('GET', '/admin/api/logs');
  const el   = document.getElementById('log-box');
  if (!Array.isArray(logs) || !logs.length) { el.innerHTML = '<em>No logs yet</em>'; return; }
  el.innerHTML = logs.slice(-60).map(l => {
    const cls = l.level === 'ERROR' ? 'log-err' : l.level === 'WARN' ? 'log-warn' : 'log-ok';
    return \`<div class="log-entry"><span class="log-ts">\${(l.ts||'').slice(11,19)}</span> <span class="\${cls}">\${l.level||'INFO'}</span> \${(l.msg||'').replace(/</g,'&lt;')}</div>\`;
  }).join('');
  el.scrollTop = el.scrollHeight;
}

// ── Health stats ────────────────────────────────────────────────────────────
async function loadHealth() {
  try {
    const d = await fetch('/health').then(r => r.json());
    document.getElementById('s-sess').textContent = d.sessions ?? '—';
  } catch {}
}

// ── Logout ──────────────────────────────────────────────────────────────────
async function doLogout() {
  await api('POST', '/admin/logout');
  location.href = '/admin/login';
}

// ── Init ────────────────────────────────────────────────────────────────────
loadAccounts(); loadExport(); loadKeys(); loadLogs(); loadHealth();
setInterval(() => { loadAccounts(); loadLogs(); loadHealth(); }, 15000);
</script>
</body></html>`);
});

// ── Serve SPA ─────────────────────────────────────────────────────────────────
app.get("*", (req, res) => {
  // Don't catch admin routes
  if (req.path.startsWith("/admin")) return res.status(404).send("Not found");
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`[bridgegate-frontend] running on port ${PORT}`);
  if (!API_KEY)         console.warn("[warn] API_KEY not set");
  if (!API_BASE)        console.warn("[warn] API_BASE not set");
  if (!TOTP_SECRET_B32) console.warn("[warn] TOTP_SECRET not set — auto-generated (check logs)");
  if (devKeys.size === 0) console.warn("[warn] DEV_KEYS not set — /proxy/* routes are open");
  else console.log(`[auth] ${devKeys.size} developer key(s) configured`);
});
