/**
 * ko-sync Worker v1.0
 * Zentrale Datenschicht für die Axel Scanner Suite.
 *
 * Endpoints:
 *   GET  /sync/read?key=<key>        Liest einen Wert aus KV
 *   POST /sync/write?key=<key>       Schreibt einen Wert in KV (Body = JSON)
 *   GET  /sync/keys                  Listet alle Keys mit Metadaten
 *   GET  /sync/status                Status + letzte Änderungen
 *   GET  /sync/export                Exportiert alle Daten als JSON
 *   POST /sync/import                Importiert alle Daten aus JSON
 *   DELETE /sync/delete?key=<key>    Löscht einen Key
 *
 * KV Namespace Binding: KO_SYNC_KV
 *
 * Umgebungsvariablen:
 *   SYNC_SECRET   — optionaler Bearer Token für Schreibzugriff
 *                   (leer lassen für offenen Zugriff, da nur eigene Geräte)
 *
 * Keys der Scanner Suite:
 *   watchlist          Ticker-Liste KO-Scanner
 *   backlog_winners    Longtime-Winners
 *   backlog_oversold   Oversold-Kandidaten
 *   backlog_tracking   KI-Tracking
 *   scan_results       Top-20 letzte Scan-Ergebnisse
 *   admin_settings     Gewichte + Schwellenwerte
 *   alert_watchlist    ko-alert Ticker (geteilt mit ko-alert Worker)
 *
 * CORS: offen für ahsub.github.io + localhost (Entwicklung)
 */

const ALLOWED_ORIGINS = [
  "https://ahsub.github.io",
  "http://localhost:8080",
  "http://localhost:3000",
  "null" // file:// öffnen lokal
];

const ALLOWED_KEYS = new Set([
  "watchlist",
  "backlog_winners",
  "backlog_oversold",
  "backlog_tracking",
  "scan_results",
  "admin_settings",
  "alert_watchlist"
]);

const META_PREFIX = "meta:";

// ── Entry Point ───────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const corsHeaders = buildCorsHeaders(origin);

    // Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // Auth check für Schreiboperationen
      if (["POST", "DELETE"].includes(request.method)) {
        const authError = checkAuth(request, env);
        if (authError) return authError;
      }

      // Router
      if (path === "/sync/read")   return await handleRead(url, env, corsHeaders);
      if (path === "/sync/write")  return await handleWrite(url, request, env, corsHeaders);
      if (path === "/sync/keys")   return await handleKeys(env, corsHeaders);
      if (path === "/sync/status") return await handleStatus(env, corsHeaders);
      if (path === "/sync/export") return await handleExport(env, corsHeaders);
      if (path === "/sync/import") return await handleImport(request, env, corsHeaders);
      if (path === "/sync/delete") return await handleDelete(url, env, corsHeaders);

      // Root
      if (path === "/" || path === "") {
        return json({ status: "ok", service: "ko-sync v1.0", keys: [...ALLOWED_KEYS] }, corsHeaders);
      }

      return json({ error: "Not found" }, corsHeaders, 404);

    } catch (err) {
      console.error("ko-sync error:", err);
      return json({ error: String(err) }, corsHeaders, 500);
    }
  }
};

// ── Handlers ──────────────────────────────────────────────────────────────────

async function handleRead(url, env, headers) {
  const key = url.searchParams.get("key");
  if (!key) return json({ error: "key parameter required" }, headers, 400);
  if (!ALLOWED_KEYS.has(key)) return json({ error: `unknown key: ${key}` }, headers, 400);

  const value = await env.KO_SYNC_KV.get(key);
  const meta  = await env.KO_SYNC_KV.get(META_PREFIX + key);

  if (value === null) {
    return json({ key, value: null, meta: null, found: false }, headers);
  }

  let parsed;
  try { parsed = JSON.parse(value); } catch { parsed = value; }

  let parsedMeta;
  try { parsedMeta = JSON.parse(meta); } catch { parsedMeta = null; }

  return json({ key, value: parsed, meta: parsedMeta, found: true }, headers);
}

async function handleWrite(url, request, env, headers) {
  const key = url.searchParams.get("key");
  if (!key) return json({ error: "key parameter required" }, headers, 400);
  if (!ALLOWED_KEYS.has(key)) return json({ error: `unknown key: ${key}` }, headers, 400);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, headers, 400);
  }

  const now = new Date().toISOString();
  const meta = {
    updated_at: now,
    size: JSON.stringify(body).length,
    ua: request.headers.get("User-Agent")?.slice(0, 80) || "unknown"
  };

  await env.KO_SYNC_KV.put(key, JSON.stringify(body));
  await env.KO_SYNC_KV.put(META_PREFIX + key, JSON.stringify(meta));

  console.log(`write: ${key} (${meta.size} bytes) at ${now}`);
  return json({ key, ok: true, meta }, headers);
}

async function handleKeys(env, headers) {
  const result = [];
  for (const key of ALLOWED_KEYS) {
    const meta = await env.KO_SYNC_KV.get(META_PREFIX + key);
    let parsedMeta = null;
    try { parsedMeta = JSON.parse(meta); } catch {}
    result.push({ key, meta: parsedMeta });
  }
  return json({ keys: result }, headers);
}

async function handleStatus(env, headers) {
  const keys = [];
  for (const key of ALLOWED_KEYS) {
    const value = await env.KO_SYNC_KV.get(key);
    const meta  = await env.KO_SYNC_KV.get(META_PREFIX + key);
    let parsedMeta = null;
    try { parsedMeta = JSON.parse(meta); } catch {}
    keys.push({
      key,
      exists: value !== null,
      updated_at: parsedMeta?.updated_at || null,
      size: parsedMeta?.size || 0
    });
  }
  return json({
    status: "ok",
    service: "ko-sync v1.0",
    time: new Date().toISOString(),
    keys
  }, headers);
}

async function handleExport(env, headers) {
  const export_data = {};
  for (const key of ALLOWED_KEYS) {
    const value = await env.KO_SYNC_KV.get(key);
    if (value !== null) {
      try { export_data[key] = JSON.parse(value); } catch { export_data[key] = value; }
    }
  }
  return json({
    exported_at: new Date().toISOString(),
    data: export_data
  }, headers);
}

async function handleImport(request, env, headers) {
  let body;
  try { body = await request.json(); } catch {
    return json({ error: "Invalid JSON" }, headers, 400);
  }

  const data = body.data || body;
  const imported = [];
  const skipped  = [];

  for (const [key, value] of Object.entries(data)) {
    if (!ALLOWED_KEYS.has(key)) { skipped.push(key); continue; }
    const now = new Date().toISOString();
    const meta = { updated_at: now, size: JSON.stringify(value).length, ua: "import" };
    await env.KO_SYNC_KV.put(key, JSON.stringify(value));
    await env.KO_SYNC_KV.put(META_PREFIX + key, JSON.stringify(meta));
    imported.push(key);
  }

  return json({ ok: true, imported, skipped }, headers);
}

async function handleDelete(url, env, headers) {
  const key = url.searchParams.get("key");
  if (!key) return json({ error: "key parameter required" }, headers, 400);
  if (!ALLOWED_KEYS.has(key)) return json({ error: `unknown key: ${key}` }, headers, 400);

  await env.KO_SYNC_KV.delete(key);
  await env.KO_SYNC_KV.delete(META_PREFIX + key);
  return json({ key, deleted: true }, headers);
}

// ── Auth ──────────────────────────────────────────────────────────────────────
function checkAuth(request, env) {
  if (!env.SYNC_SECRET) return null; // kein Secret gesetzt = offen
  const auth = request.headers.get("Authorization") || "";
  if (auth === `Bearer ${env.SYNC_SECRET}`) return null;
  return json({ error: "Unauthorized" }, {}, 401);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function buildCorsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Content-Type": "application/json"
  };
}

function json(data, headers = {}, status = 200) {
  return new Response(JSON.stringify(data, null, 2), { status, headers });
}
