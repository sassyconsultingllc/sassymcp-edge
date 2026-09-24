// Copyright (c) 2026 Shane Smith / Sassy Consulting LLC. All rights reserved.
// Proprietary source. This notice is Copyright Management Information (17 U.S.C. 1202); removal or alteration prohibited.
// CodeMark: SCLLC1-sassymcp_edge-3KUPDORHYPPS
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import OAuthProvider, { type AuthRequest, type ClientInfo, type OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { z } from "zod";

export interface Env {
  MEMORY: KVNamespace;
  OAUTH_KV: KVNamespace;
  MCP_OBJECT: DurableObjectNamespace;
  DOWNLOADS: R2Bucket;            // R2 bucket holding the latest SassyMCP installer
  MCP_AUTH_TOKEN?: string;        // owner bearer (back-compat: always maps to userId "owner")
  MEMORY_ENC_KEY?: string;        // 64 hex chars / 32 bytes, AES-256-GCM at rest
  OAUTH_PROVIDER: OAuthHelpers;
  // --- provisioning (multi-tenant) ---
  RESEND_API_KEY?: string;        // Resend API key for emailing tokens back
  PROVISION_FROM?: string;        // e.g. "SassyMCP Edge <mcp@sassyconsultingllc.com>"
  PUBLIC_BASE_URL?: string;       // e.g. "https://mcp-edge.sassyconsultingllc.com"
  TOKEN_TTL_DAYS?: string;        // default "30"
  MAX_USERS?: string;             // soft global cap, default "500"
  ALLOWLIST_ONLY?: string;        // "1" => require allow:<email> in KV before minting
}

// Identity attached to every authenticated request and surfaced inside the
// Durable Object as `this.props`. In agents@0.15 the DO is keyed by MCP
// *session*, not by user, so per-user isolation is enforced here (props) plus
// per-user KV key namespacing in the memory tools below — NOT by per-user DOs.
type Props = { userId: string; email: string; role: "owner" | "user" };

interface TokenRecord {
  userId: string;
  email: string;
  scope: string[];
  role: "user";
  created: number;
  expires: number;
}

// --- KV key builders --------------------------------------------------------
const tokenKey = (t: string) => `token:${t}`;
const userKey = (e: string) => `user:${e.toLowerCase()}`;
const uidKey = (e: string) => `uid:${e.toLowerCase()}`;
const rlKey = (e: string) => `rl:${e.toLowerCase()}`;
const allowKey = (e: string) => `allow:${e.toLowerCase()}`;
const COUNT_KEY = "stats:user_count";
const memPrefix = (userId: string) => `mem:${userId}:`;

const DOWNLOAD_KEY = "sassymcp-latest.dxt";      // stable R2 key, overwritten each release
const DOWNLOAD_PATH = "/download/sassymcp.dxt";  // public, branded URL on this Worker

// --- encryption-at-rest helpers --------------------------------------------
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

// --- misc helpers -----------------------------------------------------------
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

function randomToken(nBytes = 32): string {
  const b = new Uint8Array(nBytes);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256Hex(s: string): Promise<string> {
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Randomized, non-derivable userId, stable per email so re-issued tokens keep
// the same private memory. The map is persistent (no TTL) and lives only in KV.
async function getOrCreateUserId(env: Env, email: string): Promise<string> {
  const existing = await env.OAUTH_KV.get(uidKey(email));
  if (existing) return existing;
  const uid = "u_" + randomToken(12);
  await env.OAUTH_KV.put(uidKey(email), uid);
  return uid;
}

// SSRF guard for fetch_url: block loopback, private, link-local/metadata, CGNAT,
// and internal-looking hostnames. The edge can reach a lot of networks, so an
// authenticated multi-tenant fetch tool must not become an open internal proxy.
function isBlockedHost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".internal") || h === "metadata.google.internal") return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = parseInt(m[1], 10);
    const b = parseInt(m[2], 10);
    if (a === 0 || a === 127 || a === 10) return true;
    if (a === 169 && b === 254) return true;     // link-local incl. cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  }
  if (h === "::1" || h.startsWith("fe80") || h.startsWith("fc") || h.startsWith("fd")) return true;
  return false;
}

const FETCH_BODY_CAP = 256 * 1024; // 256 KB returned-body cap

// --- the per-session MCP agent (Durable Object) -----------------------------
export class SassyEdgeMCP extends McpAgent<Env> {
  server = new McpServer({ name: "sassymcp-edge", version: "2.0.0" });

  private memKey: Promise<CryptoKey | null> | null = null;

  private getMemKey(): Promise<CryptoKey | null> {
    return (this.memKey ??= importMemoryKey(this.env));
  }

  private uid(): string {
    const p = this.props as Props | undefined;
    return p?.userId ?? "owner";
  }

  // Masked audit: tool invocations are recorded only as AES-256-GCM ciphertext
  // (tool name + timestamp) under the caller's namespace, never logged in
  // plaintext. Best-effort — a failure here never breaks the tool call.
  private async recordCall(tool: string): Promise<void> {
    try {
      const k = await this.getMemKey();
      if (!k) return;
      const blob = await encryptValue(k, JSON.stringify({ tool, ts: Date.now() }));
      const id = `${Date.now()}-${randomToken(4)}`;
      await this.env.MEMORY.put(`audit:${this.uid()}:${id}`, blob, { expirationTtl: 7 * 86400 });
    } catch {
      /* audit is best-effort */
    }
  }

  async init() {
    this.server.tool(
      "ping",
      "Health check. Confirms the edge MCP is alive and returns server time and the calling identity.",
      {},
      async () => {
        await this.recordCall("ping");
        return text({ ok: true, server: "sassymcp-edge", version: "2.0.0", userId: this.uid(), time: new Date().toISOString() });
      },
    );

    this.server.tool(
      "memory_set",
      "Store a value in your private edge memory (Cloudflare KV, AES-256-GCM encrypted at rest, isolated per access token). Survives across sessions and devices. Optional TTL.",
      {
        key: z.string().min(1).max(512),
        value: z.string(),
        ttl_seconds: z.number().int().min(60).optional(),
      },
      async ({ key, value, ttl_seconds }) => {
        await this.recordCall("memory_set");
        const encKey = await this.getMemKey();
        if (!encKey) {
          return text({ error: "MEMORY_ENC_KEY secret is not set (expects 64 hex chars / 32 bytes). Refusing to store plaintext." });
        }
        const stored = await encryptValue(encKey, value);
        await this.env.MEMORY.put(memPrefix(this.uid()) + key, stored, ttl_seconds ? { expirationTtl: ttl_seconds } : undefined);
        return text({ stored: key, encrypted: true, ttl_seconds: ttl_seconds ?? null });
      },
    );

    this.server.tool(
      "memory_get",
      "Read a value from your private edge memory (decrypted transparently).",
      { key: z.string().min(1).max(512) },
      async ({ key }) => {
        await this.recordCall("memory_get");
        const raw = await this.env.MEMORY.get(memPrefix(this.uid()) + key);
        if (raw === null) return text({ key, found: false });
        if (!raw.startsWith(ENC_PREFIX)) {
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
      "List the keys in your private edge memory, optionally filtered by prefix. Pages through your full keyspace.",
      { prefix: z.string().optional() },
      async ({ prefix }) => {
        await this.recordCall("memory_list");
        const base = memPrefix(this.uid());
        const scan = base + (prefix ?? "");
        const keys: string[] = [];
        let cursor: string | undefined;
        do {
          const page = await this.env.MEMORY.list({ prefix: scan, cursor });
          keys.push(...page.keys.map((k) => k.name.slice(base.length)));
          cursor = page.list_complete ? undefined : page.cursor;
        } while (cursor);
        return text({ count: keys.length, keys });
      },
    );

    this.server.tool(
      "memory_delete",
      "Delete a key from your private edge memory.",
      { key: z.string().min(1).max(512) },
      async ({ key }) => {
        await this.recordCall("memory_delete");
        await this.env.MEMORY.delete(memPrefix(this.uid()) + key);
        return text({ deleted: key });
      },
    );

    this.server.tool(
      "fetch_url",
      "HTTP request executed from Cloudflare's edge. Returns status, headers, and body text (capped at 256 KB). Public hosts only — loopback, private, link-local, and metadata addresses are blocked.",
      {
        url: z.url(),
        method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).default("GET"),
        headers: z.record(z.string(), z.string()).optional(),
        body: z.string().optional(),
      },
      async ({ url, method, headers, body }) => {
        await this.recordCall("fetch_url");
        const target = new URL(url);
        if (target.protocol !== "http:" && target.protocol !== "https:") {
          return text({ error: `unsupported protocol: ${target.protocol}` });
        }
        if (isBlockedHost(target.hostname)) {
          return text({ error: `blocked host: ${target.hostname} (loopback/private/link-local/metadata addresses are not allowed)` });
        }
        const res = await fetch(target.toString(), {
          method,
          headers,
          body: method === "GET" || method === "HEAD" ? undefined : body,
          redirect: "follow",
        });
        let responseBody = method === "HEAD" ? "" : await res.text();
        let truncated = false;
        if (responseBody.length > FETCH_BODY_CAP) {
          responseBody = responseBody.slice(0, FETCH_BODY_CAP);
          truncated = true;
        }
        return text({
          status: res.status,
          statusText: res.statusText,
          headers: Object.fromEntries(res.headers.entries()),
          body: responseBody,
          truncated,
        });
      },
    );
  }
}

// --- auth resolution --------------------------------------------------------
function timingSafeEqualStr(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.byteLength !== bb.byteLength) return false;
  return crypto.subtle.timingSafeEqual(ab, bb);
}

async function resolveBearer(env: Env, token: string): Promise<Props | null> {
  if (env.MCP_AUTH_TOKEN && env.MCP_AUTH_TOKEN.length > 0 && timingSafeEqualStr(token, env.MCP_AUTH_TOKEN)) {
    return { userId: "owner", email: "owner", role: "owner" };
  }
  const rec = (await env.OAUTH_KV.get(tokenKey(token), "json")) as TokenRecord | null;
  if (!rec) return null;
  if (rec.expires && rec.expires < Date.now()) {
    await env.OAUTH_KV.delete(tokenKey(token));
    return null;
  }
  return { userId: rec.userId, email: rec.email, role: "user" };
}

// --- R2 download ------------------------------------------------------------
async function serveDownload(env: Env): Promise<Response> {
  const obj = await env.DOWNLOADS.get(DOWNLOAD_KEY);
  if (!obj) return new Response("Installer not available yet.", { status: 404, headers: SECURITY_HEADERS });
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("Content-Type", "application/octet-stream");
  headers.set("Content-Disposition", `attachment; filename="${DOWNLOAD_KEY}"`);
  headers.set("Cache-Control", "public, max-age=300");
  if (obj.httpEtag) headers.set("ETag", obj.httpEtag);
  return new Response(obj.body, { headers });
}

// --- email provisioning -----------------------------------------------------
async function sendMail(env: Env, to: string, subject: string, html: string): Promise<void> {
  if (!env.RESEND_API_KEY || !env.PROVISION_FROM) {
    console.log("[provision] RESEND not configured; cannot send", { subject });
    return;
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: env.PROVISION_FROM, to, subject, html }),
  });
  if (!res.ok) console.log("[provision] resend send failed", res.status);
}

function tokenEmailHtml(base: string, token: string): string {
  const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const t = esc(token);
  const root = base.replace(/\/$/, "");
  const url = `${root}/mcp`;
  const dl = `${root}${DOWNLOAD_PATH}`;
  return `<!doctype html><html><body style="font-family:system-ui,sans-serif;color:#111;line-height:1.5">
<h2>Your SassyMCP Edge access token</h2>
<p>This token is private to you. Your memory and data are isolated from every other user.</p>
<p><strong>Endpoint:</strong> <code>${esc(url)}</code></p>
<p><strong>Token:</strong><br><code style="word-break:break-all">${t}</code></p>
<h3>Claude Code</h3>
<pre style="background:#f4f4f4;padding:12px;border-radius:6px;white-space:pre-wrap">claude mcp add --transport http sassymcp-edge ${esc(url)} --header "Authorization: Bearer ${t}"</pre>
<h3>Claude Desktop / Cursor</h3>
<pre style="background:#f4f4f4;padding:12px;border-radius:6px;white-space:pre-wrap">{
  "sassymcp-edge": {
    "command": "npx",
    "args": ["-y", "mcp-remote", "${esc(url)}", "--header", "Authorization: Bearer ${t}"]
  }
}</pre>
<h3>Desktop app (optional)</h3>
<p>Install the latest SassyMCP desktop extension: <a href="${esc(dl)}">${esc(dl)}</a><br>
<span style="color:#888;font-size:0.9em">Always the current release — served from our network.</span></p>
<p style="color:#888;font-size:0.9em">Lost your token? Email this address again and a fresh one will replace it.</p>
</body></html>`;
}

async function handleProvisionEmail(message: ForwardableEmailMessage, env: Env): Promise<void> {
  const from = (message.from ?? "").toLowerCase().trim();
  if (!from || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(from)) return;
  const base = env.PUBLIC_BASE_URL ?? "https://mcp-edge.sassyconsultingllc.com";

  if (env.ALLOWLIST_ONLY === "1") {
    const allowed = await env.OAUTH_KV.get(allowKey(from));
    if (!allowed) {
      await sendMail(env, from, "SassyMCP Edge — access request received",
        "<p>Your address isn't on the allowlist yet. The operator has been notified.</p>");
      return;
    }
  }

  const prevToken = await env.OAUTH_KV.get(userKey(from));
  const isReturning = !!prevToken;

  // Per-sender rate limit: one mint per 24h; a repeat re-sends the live token.
  // Replies go to message.from (the real mailbox), so a spoofed From can never
  // receive a usable token — receiving the reply is the verification.
  const rl = await env.OAUTH_KV.get(rlKey(from));
  if (rl && isReturning) {
    await sendMail(env, from, "Your SassyMCP Edge access token", tokenEmailHtml(base, prevToken!));
    return;
  }

  const cap = parseInt(env.MAX_USERS ?? "500", 10);
  const countRaw = await env.OAUTH_KV.get(COUNT_KEY);
  const count = countRaw ? parseInt(countRaw, 10) : 0;
  if (!isReturning && count >= cap) {
    await sendMail(env, from, "SassyMCP Edge — signups temporarily full", "<p>The free tier is at capacity right now. Please try again later.</p>");
    return;
  }

  const userId = await getOrCreateUserId(env, from);
  const ttlDays = parseInt(env.TOKEN_TTL_DAYS ?? "30", 10);
  const ttl = ttlDays * 86400;

  if (prevToken) await env.OAUTH_KV.delete(tokenKey(prevToken));

  const token = randomToken(32);
  const rec: TokenRecord = { userId, email: from, scope: ["mcp"], role: "user", created: Date.now(), expires: Date.now() + ttl * 1000 };
  await env.OAUTH_KV.put(tokenKey(token), JSON.stringify(rec), { expirationTtl: ttl });
  await env.OAUTH_KV.put(userKey(from), token, { expirationTtl: ttl });
  await env.OAUTH_KV.put(rlKey(from), "1", { expirationTtl: 86400 });
  if (!isReturning) await env.OAUTH_KV.put(COUNT_KEY, String(count + 1));

  await sendMail(env, from, "Your SassyMCP Edge access token", tokenEmailHtml(base, token));
}

// --- security headers + authorize page --------------------------------------
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
  .hint { color: #888; font-size: 0.8rem; margin-top: 0.8rem; }
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
    <input type="password" name="key" placeholder="Your access token" autocomplete="off" required>
    <button type="submit">Approve</button>
  </form>
  <p class="hint">Paste the access token emailed to you. Don't have one? Email the provisioning address to receive a token.</p>
</div></body></html>`;
}

const defaultHandler = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/" && request.method === "GET") {
      return new Response("sassymcp-edge — multi-tenant MCP. Endpoint /mcp (streamable HTTP) and /sse (legacy). Auth: per-user bearer token (email the provisioning address) or OAuth using that token.", {
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
      // The consent "key" is the user's own issued token (or the owner token).
      const props = await resolveBearer(env, key);
      if (!props) {
        const client = await env.OAUTH_PROVIDER.lookupClient(authReq.clientId).catch(() => null);
        return new Response(authorizePage(client, authReq, "Invalid or expired access token."), { status: 403, headers: HTML_HEADERS });
      }
      const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
        request: authReq,
        userId: props.userId,
        metadata: { approvedAt: new Date().toISOString() },
        scope: authReq.scope,
        props,
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

    // Public installer download — branded URL on this Worker, streamed from R2.
    if (request.method === "GET" && url.pathname === DOWNLOAD_PATH) {
      return serveDownload(env);
    }

    const isMcp = url.pathname === "/mcp" || url.pathname.startsWith("/mcp/");
    const isSse = url.pathname === "/sse" || url.pathname.startsWith("/sse/");

    // Per-user bearer fast path: resolve identity, inject it as ctx.props so the
    // McpAgent session runs as that user (memory tools namespace on it). Falls
    // through to the OAuth provider for OAuth-minted tokens and the auth pages.
    if (isMcp || isSse) {
      const m = (request.headers.get("authorization") ?? "").match(/^Bearer\s+(.+)$/i);
      if (m) {
        const props = await resolveBearer(env, m[1]);
        if (props) {
          (ctx as unknown as { props?: Props }).props = props;
          const handler = isSse ? SassyEdgeMCP.serveSSE("/sse") : SassyEdgeMCP.serve("/mcp");
          return handler.fetch(request, env, ctx);
        }
      }
    }
    return oauth.fetch(request, env, ctx);
  },

  async email(message: ForwardableEmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(handleProvisionEmail(message, env));
  },
};
