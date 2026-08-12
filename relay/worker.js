const MAX_BLOB_SIZE = 65536; // 64KB
const DEFAULT_TTL = 86400;  // 24 hours
const MAX_KEY_SIZE = 256;   // pubkey max bytes

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/health") {
      return new Response("ok");
    }

    // Public key registry: /k/<username>
    const keyMatch = path.match(/^\/k\/([a-zA-Z0-9_-]{1,64})$/);
    if (keyMatch) {
      const username = keyMatch[1];

      if (request.method === "PUT") {
        const body = await request.text();
        if (!body || body.length > MAX_KEY_SIZE) {
          return new Response("invalid key", { status: 400 });
        }
        if (!body.startsWith("vault1")) {
          return new Response("invalid key format", { status: 400 });
        }
        await env.VAULT_DROPS.put("pubkey:" + username, body);
        return new Response("ok", { status: 201 });
      }

      if (request.method === "GET") {
        const key = await env.VAULT_DROPS.get("pubkey:" + username);
        if (!key) {
          return new Response("not found", { status: 404 });
        }
        return new Response(key);
      }

      return new Response("method not allowed", { status: 405 });
    }

    // Dead-drop mailboxes: /m/<mailbox_id>
    const dropMatch = path.match(/^\/m\/([a-zA-Z0-9_-]{32,128})$/);
    if (!dropMatch) {
      return new Response("not found", { status: 404 });
    }

    const mailbox = dropMatch[1];

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
