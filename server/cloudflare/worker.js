// sshield sync server for Cloudflare Workers (free plan) + one KV namespace.
// Zero-knowledge: it stores the client-side-encrypted vault file as an opaque blob,
// keyed by sha256(bearer token). It never sees passwords, hosts or keys.
//
//   HEAD /v1/vault  -> 200 + ETag: "<rev>"  | 404
//   GET  /v1/vault  -> 200 blob + ETag      | 404
//   PUT  /v1/vault  If-Match: "<rev>" (or "0" to create, "*" to force) -> 200 {rev} | 409 {rev}

const MAX_BYTES = 1024 * 1024; // 1 MiB of ciphertext is plenty for thousands of hosts

async function sha256hex(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...extra } });

// ---- Shared terminal sessions -------------------------------------------------
// One Durable Object per room. The relay forwards opaque, end-to-end encrypted frames:
//   host -> every guest, guest -> host. Clients encrypt with a key that never leaves the
//   share link's fragment, so the relay learns nothing about the terminal contents.
//   GET /v1/room/<32 hex>?role=host&hs=<host secret>   (WebSocket)
//   GET /v1/room/<32 hex>?role=guest                    (WebSocket)
const MAX_GUESTS = 8;
const MAX_FRAME = 256 * 1024;

export class Room {
  constructor(state) {
    this.state = state;
  }

  guestCount() {
    return this.state.getWebSockets("guest").length;
  }

  notifyHost() {
    for (const h of this.state.getWebSockets("host")) h.send(JSON.stringify({ t: "guests", n: this.guestCount() }));
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") return new Response("expected websocket", { status: 426 });
    const url = new URL(request.url);
    const role = url.searchParams.get("role");
    if (role === "host") {
      const hs = url.searchParams.get("hs") || "";
      if (!/^[0-9a-f]{32,128}$/.test(hs)) return new Response("bad host secret", { status: 400 });
      const stored = await this.state.storage.get("hs");
      if (stored === undefined) await this.state.storage.put("hs", hs);
      else if (stored !== hs) return new Response("forbidden", { status: 403 });
      for (const old of this.state.getWebSockets("host")) old.close(1000, "replaced");
    } else if (role === "guest") {
      if ((await this.state.storage.get("hs")) === undefined) return new Response("no such session", { status: 404 });
      if (this.state.getWebSockets("host").length === 0) return new Response("host is not online", { status: 404 });
      if (this.guestCount() >= MAX_GUESTS) return new Response("room full", { status: 429 });
    } else {
      return new Response("bad role", { status: 400 });
    }
    const pair = new WebSocketPair();
    this.state.acceptWebSocket(pair[1], [role]);
    this.notifyHost();
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  webSocketMessage(ws, msg) {
    const size = typeof msg === "string" ? msg.length : msg.byteLength;
    if (size > MAX_FRAME || typeof msg === "string") return;
    const isHost = this.state.getTags(ws).includes("host");
    for (const peer of this.state.getWebSockets(isHost ? "guest" : "host")) peer.send(msg);
  }

  webSocketClose(ws) {
    const wasHost = this.state.getTags(ws).includes("host");
    if (wasHost && this.state.getWebSockets("host").filter((w) => w !== ws).length === 0) {
      for (const g of this.state.getWebSockets("guest")) g.close(1000, "host ended the session");
      this.state.storage.deleteAll();
    } else {
      this.notifyHost();
    }
  }

  webSocketError(ws) {
    ws.close(1011, "error");
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const room = url.pathname.match(/^\/v1\/room\/([0-9a-f]{32})$/);
    if (room) return env.ROOMS.get(env.ROOMS.idFromName(room[1])).fetch(request);
    if (url.pathname !== "/v1/vault") {
      return url.pathname === "/" ? new Response("sshield sync server\n") : json({ error: "not found" }, 404);
    }
    const auth = request.headers.get("authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (!/^[0-9a-f]{64}$/.test(token)) return json({ error: "bad token" }, 401);
    const key = "v:" + (await sha256hex(token));

    const { value, metadata } = await env.VAULTS.getWithMetadata(key, "arrayBuffer");
    const rev = metadata?.rev ?? 0;

    if (request.method === "HEAD" || request.method === "GET") {
      if (value === null) return new Response(request.method === "HEAD" ? null : JSON.stringify({ error: "empty" }), { status: 404 });
      return new Response(request.method === "HEAD" ? null : value, {
        status: 200,
        headers: { "content-type": "application/json", etag: `"${rev}"` },
      });
    }

    if (request.method === "PUT") {
      const len = Number(request.headers.get("content-length") || 0);
      if (len > MAX_BYTES) return json({ error: "too large" }, 413);
      const body = await request.arrayBuffer();
      if (body.byteLength > MAX_BYTES) return json({ error: "too large" }, 413);
      // sanity check: looks like an sshield vault envelope (still opaque ciphertext)
      try {
        const env_ = JSON.parse(new TextDecoder().decode(body));
        if (env_.v !== 1 || typeof env_.ct !== "string") throw new Error();
      } catch {
        return json({ error: "not a vault envelope" }, 400);
      }
      const ifMatch = (request.headers.get("if-match") || "").replace(/"/g, "");
      if (ifMatch !== "*" && Number(ifMatch) !== rev) return json({ error: "conflict", rev }, 409);
      const next = rev + 1;
      await env.VAULTS.put(key, body, { metadata: { rev: next } });
      return json({ rev: next }, 200, { etag: `"${next}"` });
    }
    return json({ error: "method not allowed" }, 405);
  },
};
