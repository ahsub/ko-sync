// ko-sync-worker.js v2.0
// Cloudflare Worker — KV-Sync für UnderlyingIQ mit Token-Isolation
// 
// ÄNDERUNG v2.0 (12.07.2026): Token-basierte Nutzer-Isolation
// Jeder Nutzer setzt einmalig ein selbst gewähltes UIQ-Sync-Token (6-32 Zeichen).
// Alle KV-Keys werden als `{token}:{key}` gespeichert — vollständige Datentrennung
// zwischen verschiedenen Nutzern ohne serverseitige Benutzerverwaltung.
//
// Header: X-UIQ-Token: <token>
// Erlaubte Keys: watchlist, backlog_winners, backlog_oversold, backlog_tracking,
//                scan_results, admin_settings, alert_watchlist
// Endpoints:
//   GET  /sync/status          → Status aller eigenen Keys
//   GET  /sync/:key            → Eigenen Key lesen
//   POST /sync/:key            → Eigenen Key schreiben
//   DELETE /sync/all           → Alle eigenen Keys löschen (Konto-Reset)

const ALLOWED_KEYS = new Set([
  'watchlist', 'backlog_winners', 'backlog_oversold', 'backlog_tracking',
  'scan_results', 'admin_settings', 'alert_watchlist'
]);

const TOKEN_MIN = 6;
const TOKEN_MAX = 32;
// Erlaubte Zeichen: alphanumerisch + Bindestrich + Unterstrich
const TOKEN_RE  = /^[a-zA-Z0-9_\-]+$/;

export default {
  async fetch(request, env) {
    const url  = new URL(request.url);
    const path = url.pathname;

    const cors = {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-UIQ-Token',
      'Content-Type': 'application/json'
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }


    // ── GET /public/master_market_data — öffentlich, kein Token nötig ─────────
    // Liest master_market_data direkt aus KV (read-only, kein User-Prefix).
    // Wird von loadKVMasterData() im Frontend genutzt.
    if (path === '/public/master_market_data' && request.method === 'GET') {
      try {
        const raw = await env.KO_SYNC_KV.get('master_market_data', { type: 'text' });
        if (!raw) {
          return new Response(JSON.stringify({ error: 'master_market_data nicht im KV' }),
            { status: 404, headers: cors });
        }
        return new Response(raw, {
          headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300' }
        });
      } catch(e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: cors });
      }
    }


    // ── GET /public/options_watchlist — öffentlich, kein Token nötig ──────────
    if (path === '/public/options_watchlist' && request.method === 'GET') {
      try {
        const raw = await env.KO_SYNC_KV.get('options_watchlist', { type: 'text' });
        if (!raw) return new Response(JSON.stringify({ error: 'options_watchlist nicht im KV' }),
          { status: 404, headers: cors });
        return new Response(raw, {
          headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300' }
        });
      } catch(e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: cors });
      }
    }

    // ── GET /public/daily_market_snapshot — gecachtes Morning Briefing ────────
    if (path === '/public/daily_market_snapshot' && request.method === 'GET') {
      try {
        const raw = await env.KO_SYNC_KV.get('daily_market_snapshot', { type: 'text' });
        if (!raw) return new Response(JSON.stringify({ ok: false, reason: 'not_yet_generated' }),
          { status: 404, headers: cors });
        return new Response(raw, {
          headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300' }
        });
      } catch(e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: cors });
      }
    }

    // ── Token lesen + validieren ──────────────────────────────────────────────
    const token = (request.headers.get('X-UIQ-Token') || '').trim();

    // /sync/status und Schreib-/Lesezugriffe brauchen Token
    // Einzige Ausnahme: OPTIONS (oben bereits behandelt)
    if (!token) {
      return new Response(JSON.stringify({
        error:   'Kein UIQ-Sync-Token gesetzt.',
        hint:    'X-UIQ-Token Header fehlt. Token in UIQ-Einstellungen unter Cloud Sync setzen.',
        code:    'NO_TOKEN'
      }), { status: 401, headers: cors });
    }

    if (token.length < TOKEN_MIN || token.length > TOKEN_MAX || !TOKEN_RE.test(token)) {
      return new Response(JSON.stringify({
        error:  'Ungültiges UIQ-Sync-Token.',
        hint:   `Token: ${TOKEN_MIN}-${TOKEN_MAX} Zeichen, nur a-z A-Z 0-9 _ -`,
        code:   'INVALID_TOKEN'
      }), { status: 400, headers: cors });
    }

    // Alle KV-Keys mit Token-Prefix isolieren
    const pfx = token.toLowerCase() + ':';  // z.B. "axel2026:watchlist"

    // ── GET /sync/status — Status aller eigenen Keys ──────────────────────────
    if (path === '/sync/status' && request.method === 'GET') {
      const keys = [...ALLOWED_KEYS];
      const result = await Promise.all(keys.map(async (key) => {
        try {
          const val = await env.KO_SYNC_KV.getWithMetadata(pfx + key);
          return {
            key,
            exists:     val.value !== null,
            updated_at: val.metadata?.updated_at || null,
            size:       val.value ? val.value.length : 0
          };
        } catch(e) {
          return { key, exists: false, updated_at: null, size: 0 };
        }
      }));
      return new Response(JSON.stringify({
        status:  'ok',
        service: 'ko-sync v2.0',
        token:   token.slice(0, 3) + '***',  // nur Anfang zurückgeben (kein Full-Leak)
        time:    new Date().toISOString(),
        keys:    result
      }), { headers: cors });
    }

    // ── DELETE /sync/all — alle eigenen Keys löschen ──────────────────────────
    if (path === '/sync/all' && request.method === 'DELETE') {
      const keys   = [...ALLOWED_KEYS];
      let deleted = 0;
      for (const key of keys) {
        try {
          await env.KO_SYNC_KV.delete(pfx + key);
          deleted++;
        } catch(e) { /* silent */ }
      }
      return new Response(JSON.stringify({
        ok: true, deleted, token: token.slice(0, 3) + '***'
      }), { headers: cors });
    }

    // ── Match /sync/:key ──────────────────────────────────────────────────────
    const match = path.match(/^\/sync\/([a-z0-9_]+)$/);
    if (!match) {
      return new Response(JSON.stringify({ error: 'Not found', path }), {
        status: 404, headers: cors
      });
    }
    const key = match[1];

    // Nur erlaubte Keys
    if (key !== 'status' && !ALLOWED_KEYS.has(key)) {
      return new Response(JSON.stringify({
        error: `Unbekannter Key: ${key}`,
        allowed: [...ALLOWED_KEYS]
      }), { status: 400, headers: cors });
    }

    const kvKey = pfx + key;  // z.B. "axel2026:watchlist"

    // ── GET /sync/:key ────────────────────────────────────────────────────────
    if (request.method === 'GET') {
      try {
        const result = await env.KO_SYNC_KV.getWithMetadata(kvKey, { type: 'json' });
        if (result.value === null) {
          return new Response(JSON.stringify({ key, data: null, updated_at: null }),
            { headers: cors });
        }
        return new Response(JSON.stringify({
          key,
          data:       result.value,
          updated_at: result.metadata?.updated_at || null
        }), { headers: cors });
      } catch(e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500, headers: cors
        });
      }
    }

    // ── POST /sync/:key ───────────────────────────────────────────────────────
    if (request.method === 'POST') {
      try {
        const body       = await request.json();
        const updated_at = Date.now();
        await env.KO_SYNC_KV.put(kvKey, JSON.stringify(body.data), {
          metadata: { updated_at, token_prefix: token.slice(0, 3) }
        });
        return new Response(JSON.stringify({ ok: true, key, updated_at }),
          { headers: cors });
      } catch(e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500, headers: cors
        });
      }
    }

    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405, headers: cors
    });
  }
};
