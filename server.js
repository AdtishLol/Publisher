import express from "express";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const { ROBLOX_API_KEY, ALLOWED_TARGETS = "", APP_TOKEN, CONFIRM_SECRET, PORT = 3000 } = process.env;
for (const [k, v] of Object.entries({ ROBLOX_API_KEY, APP_TOKEN, CONFIRM_SECRET })) {
  if (!v) { console.error(`Missing env var ${k}`); process.exit(1); }
}
const targets = new Set(ALLOWED_TARGETS.split(",").map(s => s.trim()).filter(Boolean));
const MAX_BYTES = 100 * 1024 * 1024;
const CONFIRM_TTL_MS = 5 * 60 * 1000;
const API = "https://apis.roblox.com/universes/v1";

const app = express();
const here = path.dirname(fileURLToPath(import.meta.url));
app.get("/", (_q, res) => res.sendFile(path.join(here, "index.html")));
app.use(express.raw({ type: "*/*", limit: MAX_BYTES }));

const log = (...a) => console.log(new Date().toISOString(), ...a); // never logs the API key
const fail = (res, status, error) => res.status(status).json({ ok: false, error });

// --- simple per-IP rate limit (Roblox itself allows only ~10-30 publishes/min) ---
const hits = new Map();
app.use((req, res, next) => {
  const now = Date.now(), arr = (hits.get(req.ip) || []).filter(t => now - t < 60000);
  arr.push(now); hits.set(req.ip, arr);
  arr.length > 20 ? fail(res, 429, "Too many requests. Wait a minute.") : next();
});

// --- app auth ---
app.use("/api", (req, res, next) => {
  const given = Buffer.from((req.get("authorization") || "").replace(/^Bearer /, ""));
  const want = Buffer.from(APP_TOKEN);
  if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) return fail(res, 401, "Unauthorized.");
  next();
});

// --- shared parsing / validation ---
function parse(req) {
  const universeId = String(req.query.universeId || ""), placeId = String(req.query.placeId || "");
  const versionType = req.query.versionType || "Saved";
  if (!/^\d+$/.test(universeId) || !/^\d+$/.test(placeId)) return { error: "universeId and placeId must be numeric." };
  if (!["Saved", "Published"].includes(versionType)) return { error: "versionType must be Saved or Published." };
  if (!targets.has(`${universeId}:${placeId}`)) return { error: "This universe/place is not in the server's allowed targets." };
  const body = req.body;
  if (!Buffer.isBuffer(body) || body.length === 0) return { error: "Send the place file as the raw request body." };
  const head = body.subarray(0, 64).toString("latin1");
  let format;
  if (head.startsWith("<roblox!")) format = "rbxl";
  else if (head.trimStart().startsWith("<roblox ") || head.trimStart().startsWith("<?xml")) format = "rbxlx";
  else return { error: "Not a valid Roblox place file (.rbxl or .rbxlx)." };
  if (format === "rbxlx" && !body.toString("utf8").trimEnd().endsWith("</roblox>")) return { error: "The .rbxlx file looks truncated (missing </roblox>)." };
  const sha = crypto.createHash("sha256").update(body).digest("hex");
  return { universeId, placeId, versionType, format, sha, bytes: body.length };
}
const sign = p => crypto.createHmac("sha256", CONFIRM_SECRET)
  .update(`${p.sha}|${p.universeId}|${p.placeId}|${p.versionType}|${p.exp}`).digest("hex");

// Step 1: validate the exact file and get a short-lived confirmation token.
app.post("/api/validate", (req, res) => {
  const p = parse(req);
  if (p.error) return fail(res, 400, p.error);
  const exp = Date.now() + CONFIRM_TTL_MS;
  res.json({ ok: true, format: p.format, bytes: p.bytes, sha256: p.sha, target: `${p.universeId}:${p.placeId}`,
    versionType: p.versionType, confirmToken: `${exp}.${sign({ ...p, exp })}`, expiresInSeconds: CONFIRM_TTL_MS / 1000 });
});

// Step 2: publish the same bytes, only with explicit confirmation.
app.post("/api/publish", async (req, res) => {
  const p = parse(req);
  if (p.error) return fail(res, 400, p.error);
  if (req.query.confirm !== "true") return fail(res, 400, "Publishing requires confirm=true.");
  const [expStr, sig = ""] = String(req.query.confirmToken || "").split(".");
  const exp = Number(expStr), good = sign({ ...p, exp });
  if (!exp || exp < Date.now() || sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good)))
    return fail(res, 400, "Confirmation token is missing, expired, or doesn't match this exact file/target. Run /api/validate again.");

  const url = `${API}/${p.universeId}/places/${p.placeId}/versions?versionType=${p.versionType}`;
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "x-api-key": ROBLOX_API_KEY, "Content-Type": p.format === "rbxl" ? "application/octet-stream" : "application/xml" },
      body: req.body,
      signal: AbortSignal.timeout(120000),
    });
    const text = await r.text();
    log("publish", p.universeId, p.placeId, p.versionType, "->", r.status);
    if (!r.ok) {
      const hint = { 401: "API key is invalid or expired.", 403: "Key lacks universe-places Write for this experience, or its IP allowlist blocks this server.",
        404: "Universe or place not found.", 429: "Roblox rate limit hit. Retry later." }[r.status] || "Roblox rejected the request.";
      return fail(res, r.status === 429 ? 429 : 502, `${hint} (Roblox ${r.status}: ${text.slice(0, 300)})`);
    }
    let versionNumber;
    try { versionNumber = JSON.parse(text).versionNumber; } catch {}
    if (typeof versionNumber !== "number") return fail(res, 502, `Roblox returned 200 but no versionNumber, so success is unconfirmed: ${text.slice(0, 300)}`);
    res.json({ ok: true, versionNumber, versionType: p.versionType, target: `${p.universeId}:${p.placeId}` });
  } catch (e) {
    log("publish error", e.name);
    fail(res, 502, e.name === "TimeoutError" ? "Roblox request timed out." : `Could not reach Roblox: ${e.message}`);
  }
});

app.use((err, _req, res, _next) => fail(res, err.status || 500, err.type === "entity.too.large" ? "File exceeds 100 MB." : "Server error."));
app.listen(PORT, () => log(`Publisher listening on :${PORT}, ${targets.size} allowed target(s)`));
