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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
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
