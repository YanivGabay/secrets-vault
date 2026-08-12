const MAX_BLOB_SIZE = 65536; // 64KB
const DEFAULT_TTL = 86400;  // 24 hours

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/health") {
      return new Response("ok");
    }

    const match = path.match(/^\/m\/([a-zA-Z0-9_-]{32,128})$/);
    if (!match) {
      return new Response("not found", { status: 404 });
    }

    const mailbox = match[1];

    if (request.method === "PUT") {
      const blob = await request.arrayBuffer();
      if (blob.byteLength === 0) {
        return new Response("empty payload", { status: 400 });
      }
      if (blob.byteLength > MAX_BLOB_SIZE) {
        return new Response("payload too large", { status: 413 });
      }

      const ttl = parseInt(url.searchParams.get("ttl")) || DEFAULT_TTL;
      const clampedTtl = Math.min(Math.max(ttl, 60), DEFAULT_TTL);

      await env.VAULT_DROPS.put(mailbox, blob, { expirationTtl: clampedTtl });
      return new Response("ok", { status: 201 });
    }

    if (request.method === "GET") {
      const blob = await env.VAULT_DROPS.get(mailbox, { type: "arrayBuffer" });
      if (!blob) {
        return new Response("not found", { status: 404 });
      }

      // Burn on read
      await env.VAULT_DROPS.delete(mailbox);

      return new Response(blob, {
        headers: { "Content-Type": "application/octet-stream" },
      });
    }

    return new Response("method not allowed", { status: 405 });
  },
};
