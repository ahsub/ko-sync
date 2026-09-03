var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// ko-sync-worker.js
var ALLOWED_KEYS = /* @__PURE__ */ new Set([
  "watchlist",
  "backlog_winners",
  "backlog_oversold",
  "backlog_tracking",
  "scan_results",
  "admin_settings",
  "alert_watchlist",
  "market_strip_snapshot"
]);
var TOKEN_MIN = 6;
var TOKEN_MAX = 32;
var TOKEN_RE = /^[a-zA-Z0-9_\-]+$/;
var KI_SENSITIVE_SHORTLIST = ["trigger", "stopLoss", "target", "crv", "holdingDays", "positionPct", "leverageRec"];
var KI_SENSITIVE_OPTIONS_LEGACY = ["strikeSuggestion", "dte", "deltaTarget", "premiumEstimate"];
function stripKiFields(item, sensitiveKeys) {
  if (!item || !item.ki) return item;
  const ki = { ...item.ki };
  for (const k of sensitiveKeys) delete ki[k];
  return { ...item, ki };
}
__name(stripKiFields, "stripKiFields");
function stripKiEic(item) {
  if (!item || !item.ki_eic) return item;
  const { ki_eic, ...rest } = item;
  return rest;
}
__name(stripKiEic, "stripKiEic");
function sanitizeOptionsItem(item) {
  return stripKiEic(stripKiFields(item, KI_SENSITIVE_OPTIONS_LEGACY));
}
__name(sanitizeOptionsItem, "sanitizeOptionsItem");
function sanitizeMasterMarketData(obj) {
  if (obj && Array.isArray(obj.masterShortlist)) {
    obj.masterShortlist = obj.masterShortlist.map((c) => stripKiFields(c, KI_SENSITIVE_SHORTLIST));
  }
  if (obj && Array.isArray(obj.optionsWatchlist)) {
    obj.optionsWatchlist = obj.optionsWatchlist.map(sanitizeOptionsItem);
  }
  return obj;
}
__name(sanitizeMasterMarketData, "sanitizeMasterMarketData");
function sanitizeOptionsWatchlist(obj) {
  if (Array.isArray(obj)) {
    return obj.map(sanitizeOptionsItem);
  }
  if (obj && Array.isArray(obj.tickers)) {
    obj.tickers = obj.tickers.map(sanitizeOptionsItem);
  }
  return obj;
}
__name(sanitizeOptionsWatchlist, "sanitizeOptionsWatchlist");
var ko_sync_worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-UIQ-Token, Authorization",
      "Content-Type": "application/json"
    };
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }
    function checkPublicAuth() {
      const authHeader = request.headers.get("Authorization") || "";
      const bearer = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
      const isOwner = !!env.OWNER_TOKEN && bearer === env.OWNER_TOKEN;
      const isValid = isOwner || !!env.STATIC_TOKEN && bearer === env.STATIC_TOKEN;
      return { isValid, isOwner };
    }
    __name(checkPublicAuth, "checkPublicAuth");
    if (path === "/public/master_market_data" && request.method === "GET") {
      const { isValid, isOwner } = checkPublicAuth();
      if (!isValid) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: cors });
      }
      try {
        const raw = await env.KO_SYNC_KV.get("master_market_data", { type: "text" });
        if (!raw) {
          return new Response(
            JSON.stringify({ error: "master_market_data nicht im KV" }),
            { status: 404, headers: cors }
          );
        }
        if (isOwner) {
          return new Response(raw, {
            headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "private, max-age=300" }
          });
        }
        let parsed;
        try {
          parsed = JSON.parse(raw);
        } catch (e) {
          return new Response(raw, { headers: { ...cors, "Content-Type": "application/json" } });
        }
        parsed = sanitizeMasterMarketData(parsed);
        return new Response(JSON.stringify(parsed), {
          headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "private, max-age=300" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: cors });
      }
    }
    if (path === "/public/options_watchlist" && request.method === "GET") {
      const { isValid, isOwner } = checkPublicAuth();
      if (!isValid) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: cors });
      }
      try {
        const raw = await env.KO_SYNC_KV.get("options_watchlist", { type: "text" });
        if (!raw) return new Response(
          JSON.stringify({ error: "options_watchlist nicht im KV" }),
          { status: 404, headers: cors }
        );
        if (isOwner) {
          return new Response(raw, {
            headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "private, max-age=300" }
          });
        }
        let parsed;
        try {
          parsed = JSON.parse(raw);
        } catch (e) {
          return new Response(raw, { headers: { ...cors, "Content-Type": "application/json" } });
        }
        parsed = sanitizeOptionsWatchlist(parsed);
        return new Response(JSON.stringify(parsed), {
          headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "private, max-age=300" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: cors });
      }
    }
    if (path === "/public/daily_market_snapshot" && request.method === "GET") {
      const { isValid } = checkPublicAuth();
      if (!isValid) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: cors });
      }
      try {
        const raw = await env.KO_SYNC_KV.get("daily_market_snapshot", { type: "text" });
        if (!raw) return new Response(
          JSON.stringify({ ok: false, reason: "not_yet_generated" }),
          { status: 404, headers: cors }
        );
        return new Response(raw, {
          headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "private, max-age=300" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: cors });
      }
    }
    if (path === "/public/daily_market_snapshot_us" && request.method === "GET") {
      const { isValid } = checkPublicAuth();
      if (!isValid) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: cors });
      }
      try {
        const raw = await env.KO_SYNC_KV.get("daily_market_snapshot_us", { type: "text" });
        if (!raw) return new Response(
          JSON.stringify({ ok: false, reason: "not_yet_generated" }),
          { status: 404, headers: cors }
        );
        return new Response(raw, {
          headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "private, max-age=300" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: cors });
      }
    }
    const token = (request.headers.get("X-UIQ-Token") || "").trim();
    if (!token) {
      return new Response(JSON.stringify({
        error: "Kein UIQ-Sync-Token gesetzt.",
        hint: "X-UIQ-Token Header fehlt. Token in UIQ-Einstellungen unter Cloud Sync setzen.",
        code: "NO_TOKEN"
      }), { status: 401, headers: cors });
    }
    if (token.length < TOKEN_MIN || token.length > TOKEN_MAX || !TOKEN_RE.test(token)) {
      return new Response(JSON.stringify({
        error: "Ung\xFCltiges UIQ-Sync-Token.",
        hint: `Token: ${TOKEN_MIN}-${TOKEN_MAX} Zeichen, nur a-z A-Z 0-9 _ -`,
        code: "INVALID_TOKEN"
      }), { status: 400, headers: cors });
    }
    const pfx = token.toLowerCase() + ":";
    if (path === "/sync/status" && request.method === "GET") {
      const keys = [...ALLOWED_KEYS];
      const result = await Promise.all(keys.map(async (key2) => {
        try {
          const val = await env.KO_SYNC_KV.getWithMetadata(pfx + key2);
          return {
            key: key2,
            exists: val.value !== null,
            updated_at: val.metadata?.updated_at || null,
            size: val.value ? val.value.length : 0
          };
        } catch (e) {
          return { key: key2, exists: false, updated_at: null, size: 0 };
        }
      }));
      return new Response(JSON.stringify({
        status: "ok",
        service: "ko-sync v2.2",
        token: token.slice(0, 3) + "***",
        // nur Anfang zurückgeben (kein Full-Leak)
        time: (/* @__PURE__ */ new Date()).toISOString(),
        keys: result
      }), { headers: cors });
    }
    if (path === "/sync/all" && request.method === "DELETE") {
      const keys = [...ALLOWED_KEYS];
      let deleted = 0;
      for (const key2 of keys) {
        try {
          await env.KO_SYNC_KV.delete(pfx + key2);
          deleted++;
        } catch (e) {
        }
      }
      return new Response(JSON.stringify({
        ok: true,
        deleted,
        token: token.slice(0, 3) + "***"
      }), { headers: cors });
    }
    const match = path.match(/^\/sync\/([a-z0-9_]+)$/);
    if (!match) {
      return new Response(JSON.stringify({ error: "Not found", path }), {
        status: 404,
        headers: cors
      });
    }
    const key = match[1];
    if (key !== "status" && !ALLOWED_KEYS.has(key)) {
      return new Response(JSON.stringify({
        error: `Unbekannter Key: ${key}`,
        allowed: [...ALLOWED_KEYS]
      }), { status: 400, headers: cors });
    }
    const kvKey = pfx + key;
    if (request.method === "GET") {
      try {
        const result = await env.KO_SYNC_KV.getWithMetadata(kvKey, { type: "json" });
        if (result.value === null) {
          return new Response(
            JSON.stringify({ key, data: null, updated_at: null }),
            { headers: cors }
          );
        }
        return new Response(JSON.stringify({
          key,
          data: result.value,
          updated_at: result.metadata?.updated_at || null
        }), { headers: cors });
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500,
          headers: cors
        });
      }
    }
    if (request.method === "POST") {
      try {
        const body = await request.json();
        const updated_at = Date.now();
        await env.KO_SYNC_KV.put(kvKey, JSON.stringify(body.data), {
          metadata: { updated_at, token_prefix: token.slice(0, 3) }
        });
        return new Response(
          JSON.stringify({ ok: true, key, updated_at }),
          { headers: cors }
        );
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500,
          headers: cors
        });
      }
    }
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: cors
    });
  }
};
export {
  ko_sync_worker_default as default
};
//# sourceMappingURL=ko-sync-worker.js.map
