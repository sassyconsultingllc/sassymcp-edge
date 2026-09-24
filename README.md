<!--
   Copyright (c) 2026 Shane Smith / Sassy Consulting LLC. All rights reserved.
   Proprietary source. This notice is Copyright Management Information (17 U.S.C. 1202); removal or alteration prohibited.
   CodeMark: SCLLC1-sassymcp_edge-U4DF5UOLUULT
-->
# sassymcp-edge

A multi-tenant MCP server that runs entirely on Cloudflare — no VPS, no tunnel, no machine that has to stay on. Each user gets a private, isolated instance, provisioned by email. Built on the [Agents SDK](https://developers.cloudflare.com/agents/): each MCP session runs in a SQLite-backed Durable Object (`McpAgent`), persistent state lives in Workers KV, and the whole thing deploys with one `wrangler deploy`.

Works with Claude Code, Claude Desktop, claude.ai connectors, Cursor, and any other MCP client that speaks streamable HTTP (or legacy SSE).

## Tools

| Tool | Backing | Purpose |
|---|---|---|
| `ping` | — | Liveness check, returns server time |
| `memory_set` / `memory_get` / `memory_list` / `memory_delete` | Workers KV | Persistent key/value memory, private per access token and isolated between users; `memory_list` pages through your own keyspace |
| `fetch_url` | edge `fetch()` | HTTP request from Cloudflare's network — full status, headers, and body |

Adding your own tool is one block in [src/index.ts](src/index.ts) inside `init()`:

```ts
this.server.tool("my_tool", "Description.", { arg: z.string() }, async ({ arg }) => {
  // this.env has all your wrangler.jsonc bindings (KV, D1, R2, ...)
  return text({ result: arg });
});
```

## Auth — per-user tokens, two transports

Every request resolves to an identity (`userId`) before it reaches a tool, and memory is namespaced per identity (`mem:<userId>:…`), so users never see each other's data.

1. **Bearer token** — each user gets a unique 256-bit token (issued by email, below), sent as `Authorization: Bearer <token>`, resolved against `OAUTH_KV` and compared timing-safe. The owner token (`MCP_AUTH_TOKEN`) still works and maps to `userId "owner"`.
2. **OAuth 2.1** — for clients that require the OAuth dance (claude.ai connectors). Implemented with [`@cloudflare/workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider): DCR, PKCE, refresh tokens. The authorization page asks for the user's own issued token; the resulting grant carries that user's identity.

The server fails closed — an unrecognized or expired token gets no access. Consider a Cloudflare WAF rate-limiting rule on `/authorize` for defense in depth.

## Provisioning — request a token by email

Point a Cloudflare Email Routing address (e.g. `mcp@your-domain`) at this Worker. On inbound mail the `email()` handler derives a stable `userId` from the sender, mints a unique token into `OAUTH_KV` (TTL `TOKEN_TTL_DAYS`, default 30), and emails the token plus ready-to-paste client config back **to the sender** via Resend (`RESEND_API_KEY` + `PROVISION_FROM`).

Because the token is only ever sent to the envelope sender's mailbox, a spoofed `From` can't receive a usable token — receiving the reply *is* the verification. Guards: one mint per sender per 24h (a repeat re-sends the existing token), a soft global cap (`MAX_USERS`), and an optional allowlist (`ALLOWLIST_ONLY=1` requires an `allow:<email>` KV entry). Re-emailing rotates to a fresh token while preserving the same private memory.

### Trust model: multi-tenant, isolated per token

Each MCP *session* still gets its own Durable Object, and on top of that each *user* has a distinct `userId` and a private, namespaced memory keyspace. Hand out tokens freely — one per person. Revoking a user is a single `OAUTH_KV` delete of their `token:` / `user:` keys.

## Deploy your own

```bash
git clone https://github.com/sassyconsultingllc/sassymcp-edge
cd sassymcp-edge
npm install

# 1. Create the two KV namespaces and paste their IDs into wrangler.jsonc
npx wrangler kv namespace create MEMORY
npx wrangler kv namespace create OAUTH

# 2. Deploy, then set your two secrets (each a 64-hex-char / 32-byte random value)
npx wrangler deploy
npx wrangler secret put MCP_AUTH_TOKEN     # client access key
npx wrangler secret put MEMORY_ENC_KEY     # AES-256 key for memory encryption at rest
```

Keep a copy of `MEMORY_ENC_KEY` somewhere safe — if it's lost, encrypted memory values are unrecoverable.

PowerShell token generation, if you want one made properly:

```powershell
$bytes = [byte[]]::new(32); [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
-join ($bytes | ForEach-Object { $_.ToString('x2') })
```

Your endpoint is `https://sassymcp-edge.<your-subdomain>.workers.dev/mcp` (streamable HTTP; legacy SSE at `/sse`).

### Keeping personal config out of the repo

`wrangler.jsonc` is a generic template. Put your real account ID, KV namespace IDs, and any custom-domain route in `wrangler.personal.jsonc` (gitignored) and use:

```bash
npm run deploy:personal   # wrangler deploy --config wrangler.personal.jsonc
```

A custom domain is one entry in that file (Cloudflare provisions DNS and the certificate automatically on deploy):

```jsonc
"routes": [{ "pattern": "mcp.example.com", "custom_domain": true }]
```

## Connect clients

**Claude Code:**

```bash
claude mcp add --transport http edge-mcp https://<your-endpoint>/mcp --header "Authorization: Bearer <token>"
```

**Claude Desktop** (`%APPDATA%\Claude\claude_desktop_config.json` on Windows, `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS) via the `mcp-remote` shim:

```json
"edge-mcp": {
  "command": "npx",
  "args": ["-y", "mcp-remote", "https://<your-endpoint>/mcp",
           "--header", "Authorization: Bearer <token>"]
}
```

(Use `npx.cmd` as the command on Windows.)

**claude.ai** (web/mobile): Settings → Connectors → Add custom connector → paste `https://<your-endpoint>/mcp`. The OAuth flow opens the authorization page; enter your access key once and you're connected on every device.

## Security posture

- Fail-closed auth on every MCP route; timing-safe key comparison everywhere the key is checked
- Memory values are AES-256-GCM encrypted at rest (random IV per write) with a server-held secret — ciphertext is what sits in KV and what the Cloudflare dashboard shows; `memory_set` refuses to store plaintext if `MEMORY_ENC_KEY` is unset. Key *names* stay plaintext so prefix listing works — don't put secrets in key names.
- OAuth state in a dedicated KV namespace; tokens and grants managed by `workers-oauth-provider` (codes are single-use, PKCE enforced)
- Security headers (CSP, nosniff, frame-deny, no-referrer, no-store) on all HTML/plain responses
- All user-supplied values HTML-escaped on the authorization page
- No state on the client-facing edge beyond what the protocol requires; persistent data is explicit KV writes

## Development

```bash
npm run dev          # local worker via wrangler dev
npm run typecheck
npm run deploy       # or deploy:personal
```

Gotchas: the `agents` package requires zod v4 (`z.record(keyType, valueType)`, `z.url()` instead of `z.string().url()`). The OAuth provider requires its KV binding to be named exactly `OAUTH_KV`. `McpAgent` state is per-session — anything that should persist goes in KV, not Durable Object storage.

## License

MIT
