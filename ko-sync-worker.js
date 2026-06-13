// ko-sync-worker.js v1.1
// Cloudflare Worker — KV-Sync für KO-Scanner
// Endpoints: GET/POST /sync/:key, GET /sync/status
 
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
 
    // CORS headers
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Content-Type': 'application/json'
    };
 
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }
 
    // GET /sync/status — Status aller Keys
    if (path === '/sync/status' && request.method === 'GET') {
      const keys = ['watchlist', 'backlog_winners', 'backlog_oversold', 'backlog_tracking', 'scan_results', 'admin_settings', 'alert_watchlist'];
      const result = await Promise.all(keys.map(async (key) => {
        try {
          const val = await env.KO_SYNC_KV.getWithMetadata(key);
          return {
            key,
            exists: val.value !== null,
            updated_at: val.metadata?.updated_at || null,
            size: val.value ? val.value.length : 0
          };
        } catch(e) {
          return { key, exists: false, updated_at: null, size: 0 };
        }
      }));
      return new Response(JSON.stringify({
        status: 'ok',
        service: 'ko-sync v1.1',
        time: new Date().toISOString(),
        keys: result
      }), { headers: cors });
    }
 
    // Match /sync/:key
    const match = path.match(/^\/sync\/([a-z0-9_]+)$/);
    if (!match) {
      return new Response(JSON.stringify({ error: 'Not found', path }), { status: 404, headers: cors });
    }
    const key = match[1];
 
    // GET /sync/:key — Daten lesen
    if (request.method === 'GET') {
      try {
        const result = await env.KO_SYNC_KV.getWithMetadata(key, { type: 'json' });
        if (result.value === null) {
          return new Response(JSON.stringify({ key, data: null, updated_at: null }), { headers: cors });
        }
        return new Response(JSON.stringify({
          key,
          data: result.value,
          updated_at: result.metadata?.updated_at || null
        }), { headers: cors });
      } catch(e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: cors });
      }
    }
 
    // POST /sync/:key — Daten schreiben
    if (request.method === 'POST') {
      try {
        const body = await request.json();
        const updated_at = Date.now();
        await env.KO_SYNC_KV.put(key, JSON.stringify(body.data), {
          metadata: { updated_at }
        });
        return new Response(JSON.stringify({ ok: true, key, updated_at }), { headers: cors });
      } catch(e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: cors });
      }
    }
 
    return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers: cors });
  }
};
 



