import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import OAuthProvider, { type AuthRequest, type ClientInfo, type OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { z } from "zod";

export interface Env {
  MEMORY: KVNamespace;
  OAUTH_KV: KVNamespace;
  MCP_OBJECT: DurableObjectNamespace;
  MCP_AUTH_TOKEN?: string;
  MEMORY_ENC_KEY?: string;
  OAUTH_PROVIDER: OAuthHelpers;
}

const ENC_PREFIX = "enc1:";

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToB64(buf: ArrayBuffer | Uint8Array): string {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const c of u) s += String.fromCharCode(c);
  return btoa(s);
}

function b64ToBytes(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

async function importMemoryKey(env: Env): Promise<CryptoKey | null> {
  if (!env.MEMORY_ENC_KEY || !/^[0-9a-fA-F]{64}$/.test(env.MEMORY_ENC_KEY.trim())) return null;
  return crypto.subtle.importKey("raw", hexToBytes(env.MEMORY_ENC_KEY), "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encryptValue(key: CryptoKey, plaintext: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return ENC_PREFIX + bytesToB64(iv) + ":" + bytesToB64(ct);
}

async function decryptValue(key: CryptoKey, stored: string): Promise<string> {
  const [ivB64, ctB64] = stored.slice(ENC_PREFIX.length).split(":");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(ivB64) }, key, b64ToBytes(ctB64));
  return new TextDecoder().decode(pt);
}

function text(data: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: typeof data === "string" ? data : JSON.stringify(data, null, 2),
      },
    ],
  };
}

export class SassyEdgeMCP extends McpAgent<Env> {
  server = new McpServer({ name: "sassymcp-edge", version: "1.2.0" });

  private memKey: Promise<CryptoKey | null> | null = null;

  private getMemKey(): Promise<CryptoKey | null> {
    return (this.memKey ??= importMemoryKey(this.env));
  }

  async init() {
    this.server.tool(
      "ping",
      "Health check. Confirms the edge MCP is alive and returns server time.",
      {},
      async () => text({ ok: true, server: "sassymcp-edge", time: new Date().toISOString() }),
    );

    this.server.tool(
      "memory_set",
      "Store a value in persistent edge memory (Cloudflare KV, AES-256-GCM encrypted at rest). Survives across sessions and devices. Optional TTL.",
      {
        key: z.string().min(1).max(512),
        value: z.string(),
        ttl_seconds: z.number().int().min(60).optional(),
      },
      async ({ key, value, ttl_seconds }) => {
        const encKey = await this.getMemKey();
        if (!encKey) {
          return text({ error: "MEMORY_ENC_KEY secret is not set (expects 64 hex chars / 32 bytes). Refusing to store plaintext." });
        }
        const stored = await encryptValue(encKey, value);
        await this.env.MEMORY.put(key, stored, ttl_seconds ? { expirationTtl: ttl_seconds } : undefined);
        return text({ stored: key, encrypted: true, ttl_seconds: ttl_seconds ?? null });
      },
    );

    this.server.tool(
      "memory_get",
      "Read a value from persistent edge memory (decrypted transparently).",
      { key: z.string().min(1).max(512) },
      async ({ key }) => {
        const raw = await this.env.MEMORY.get(key);
        if (raw === null) return text({ key, found: false });
        if (!raw.startsWith(ENC_PREFIX)) {
          // Legacy plaintext entry from before encryption-at-rest was added.
          return text({ key, found: true, value: raw, encrypted: false });
        }
        const encKey = await this.getMemKey();
        if (!encKey) return text({ key, found: true, error: "MEMORY_ENC_KEY secret is not set; cannot decrypt." });
        try {
          return text({ key, found: true, value: await decryptValue(encKey, raw) });
        } catch {
          return text({ key, found: true, error: "Decryption failed — MEMORY_ENC_KEY does not match the key this value was written with." });
        }
      },
    );

    this.server.tool(
      "memory_list",
      "List all keys in persistent edge memory, optionally filtered by prefix. Pages through the full set.",
      { prefix: z.string().optional() },
      async ({ prefix }) => {
        const keys: string[] = [];
        let cursor: string | undefined;
        do {
          const page = await this.env.MEMORY.list({ prefix, cursor });
          keys.push(...page.keys.map((k) => k.name));
          cursor = page.list_complete ? undefined : page.cursor;
        } while (cursor);
        return text({ count: keys.length, keys });
      },
    );

    this.server.tool(
      "memory_delete",
      "Delete a key from persistent edge memory.",
      { key: z.string().min(1).max(512) },
      async ({ key }) => {
        await this.env.MEMORY.delete(key);
        return text({ deleted: key });
      },
    );

    this.server.tool(
      "fetch_url",
      "HTTP request executed from Cloudflare's edge. Returns status, headers, and body text. Useful when the client can't reach a URL directly or wants an edge vantage point.",
      {
        url: z.url(),
        method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).default("GET"),
        headers: z.record(z.string(), z.string()).optional(),
        body: z.string().optional(),
      },
      async ({ url, method, headers, body }) => {
        const target = new URL(url);
        if (target.protocol !== "http:" && target.protocol !== "https:") {
          return text({ error: `unsupported protocol: ${target.protocol}` });
        }
        const res = await fetch(target.toString(), {
          method,
          headers,
          body: method === "GET" || method === "HEAD" ? undefined : body,
          redirect: "follow",
        });
        const responseBody = method === "HEAD" ? "" : await res.text();
        return text({
          status: res.status,
          statusText: res.statusText,
          headers: Object.fromEntries(res.headers.entries()),
          body: responseBody,
        });
      },
    );
  }
}

const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
};

const HTML_HEADERS: Record<string, string> = {
  "Content-Type": "text/html; charset=utf-8",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
  ...SECURITY_HEADERS,
};

function timingSafeEqualStr(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.byteLength !== bb.byteLength) return false;
  return crypto.subtle.timingSafeEqual(ab, bb);
}

async function staticBearerOk(request: Request, env: Env): Promise<boolean> {
  // Fail closed if the secret is missing or empty.
  if (!env.MCP_AUTH_TOKEN) return false;
  const header = request.headers.get("authorization") ?? "";
  return timingSafeEqualStr(header, `Bearer ${env.MCP_AUTH_TOKEN}`);
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function b64Encode(s: string): string {
  return btoa(String.fromCharCode(...new TextEncoder().encode(s)));
}

function b64Decode(s: string): string {
  return new TextDecoder().decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0)));
}

const PAGE_STYLE = `
  body { font-family: system-ui, sans-serif; background: #111; color: #ddd; display: flex;
         justify-content: center; padding-top: 8vh; margin: 0; }
  .card { background: #1c1c1c; border: 1px solid #333; border-radius: 8px; padding: 2rem;
          max-width: 26rem; width: 90%; }
  h1 { font-size: 1.2rem; margin-top: 0; }
  dt { color: #888; font-size: 0.8rem; margin-top: 0.6rem; }
  dd { margin: 0.1rem 0 0; word-break: break-all; }
  input[type=password] { width: 100%; box-sizing: border-box; padding: 0.5rem; margin: 1rem 0;
          background: #111; border: 1px solid #444; border-radius: 4px; color: #ddd; }
  button { width: 100%; padding: 0.6rem; background: #2563eb; color: #fff; border: none;
          border-radius: 4px; font-size: 1rem; cursor: pointer; }
  .err { color: #f87171; font-size: 0.9rem; }
`;

function authorizePage(client: ClientInfo | null, authReq: AuthRequest, error?: string): string {
  const clientName = escapeHtml(client?.clientName || client?.clientId || "Unknown client");
  const redirectUri = escapeHtml(authReq.redirectUri ?? "");
  const scopes = escapeHtml(authReq.scope.join(" ") || "(none requested)");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize MCP client</title><style>${PAGE_STYLE}</style></head>
<body><div class="card">
  <h1>Authorize MCP client</h1>
  <dl>
    <dt>Client</dt><dd>${clientName}</dd>
    <dt>Redirect URI</dt><dd>${redirectUri}</dd>
    <dt>Scopes</dt><dd>${scopes}</dd>
  </dl>
  ${error ? `<p class="err">${escapeHtml(error)}</p>` : ""}
  <form method="post" action="/authorize">
    <input type="hidden" name="authreq" value="${escapeHtml(b64Encode(JSON.stringify(authReq)))}">
    <input type="password" name="key" placeholder="Server access key" autocomplete="off" required>
    <button type="submit">Approve</button>
  </form>
</div></body></html>`;
}

const defaultHandler = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/" && request.method === "GET") {
      return new Response("sassymcp-edge — MCP endpoint at /mcp (streamable HTTP) and /sse (legacy SSE). Auth: bearer token or OAuth.", {
        headers: { "Content-Type": "text/plain; charset=utf-8", ...SECURITY_HEADERS },
      });
    }

    if (url.pathname === "/authorize" && request.method === "GET") {
      const authReq = await env.OAUTH_PROVIDER.parseAuthRequest(request);
      const client = await env.OAUTH_PROVIDER.lookupClient(authReq.clientId);
      return new Response(authorizePage(client, authReq), { headers: HTML_HEADERS });
    }

    if (url.pathname === "/authorize" && request.method === "POST") {
      const form = await request.formData();
      const key = form.get("key");
      const encoded = form.get("authreq");
      if (typeof key !== "string" || typeof encoded !== "string") {
        return new Response("Bad request", { status: 400, headers: SECURITY_HEADERS });
      }
      let authReq: AuthRequest;
      try {
        authReq = JSON.parse(b64Decode(encoded));
      } catch {
        return new Response("Bad request", { status: 400, headers: SECURITY_HEADERS });
      }
      if (!env.MCP_AUTH_TOKEN || !timingSafeEqualStr(key, env.MCP_AUTH_TOKEN)) {
        const client = await env.OAUTH_PROVIDER.lookupClient(authReq.clientId).catch(() => null);
        return new Response(authorizePage(client, authReq, "Invalid access key."), { status: 403, headers: HTML_HEADERS });
      }
      const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
        request: authReq,
        userId: "owner",
        metadata: { approvedAt: new Date().toISOString() },
        scope: authReq.scope,
        props: { auth: "oauth" },
      });
      return Response.redirect(redirectTo, 302);
    }

    return new Response("Not found", { status: 404, headers: SECURITY_HEADERS });
  },
};

const oauth = new OAuthProvider<Env>({
  apiHandlers: {
    "/mcp": SassyEdgeMCP.serve("/mcp"),
    "/sse": SassyEdgeMCP.serveSSE("/sse"),
  },
  defaultHandler,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const isMcp = url.pathname === "/mcp" || url.pathname.startsWith("/mcp/");
    const isSse = url.pathname === "/sse" || url.pathname.startsWith("/sse/");

    // Static bearer fast path for directly-configured clients; OAuth handles the rest.
    if ((isMcp || isSse) && (await staticBearerOk(request, env))) {
      const handler = isSse ? SassyEdgeMCP.serveSSE("/sse") : SassyEdgeMCP.serve("/mcp");
      return handler.fetch(request, env, ctx);
    }
    return oauth.fetch(request, env, ctx);
  },
};
