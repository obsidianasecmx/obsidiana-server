# Obsidiana Server

A Node.js HTTP/WebSocket framework with **transparent end-to-end encryption** built on the Obsidiana protocol (ECDH + AES-GCM-256 + PoW). All routes are encrypted by default — request bodies arrive already decrypted to your handlers, and responses are encrypted automatically before leaving the server.

**Requires Node.js ≥ 18. Zero runtime dependencies beyond `obsidiana-protocol` and `obsidiana-client`.**

---

## Table of Contents

- [How it works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Server Configuration](#server-configuration)
- [Routing](#routing)
  - [Encrypted routes (default)](#encrypted-routes-default)
  - [Public routes (no encryption)](#public-routes-no-encryption)
  - [Route parameters](#route-parameters)
- [Request & Response](#request--response)
- [WebSocket](#websocket)
- [Middleware](#middleware)
  - [Built-in middleware](#built-in-middleware)
  - [Custom middleware](#custom-middleware)
- [Authentication](#authentication)
  - [Encrypted cookies](#encrypted-cookies)
  - [Stateless tokens](#stateless-tokens)
  - [requireAuth / optionalAuth](#requireauth--optionalauth)
- [Static Files](#static-files)
- [Proof-of-Work (PoW)](#proof-of-work-pow)
- [Session Management](#session-management)
- [Server Identity](#server-identity)
- [Security Model](#security-model)
- [Internal Architecture](#internal-architecture)
- [API Reference](#api-reference)

---

## How it works

Obsidiana Server wraps every HTTP and WebSocket connection in a full cryptographic handshake before any application data is exchanged:

```
Client                                          Server
──────                                          ──────
GET /q  ──────────────────────────────────────► Generate PoW challenge (signed with server identity)
        ◄──────────────── CBOR({ d: blob + "." + sig })

Solve PoW, sign challenge blob with ECDSA, send ECDH public key
POST /q ──── CBOR({ d: binary offer }) ───────► Verify PoW solution + ECDSA sig + server key hash
        ◄──── CBOR(ECDH response)               Session stored, AES-GCM-256 key derived

All subsequent HTTP requests:
POST /api/data ──── CBOR({ d: encrypted }) ───► Decrypt → req.body = { ... }
               ◄─── CBOR({ d: encrypted }) ────  res.json(200, data) → encrypted automatically

WebSocket: same PoW + ECDH flow on upgrade, then all messages are encrypted.
```

The handshake endpoint is `/q`. Everything else is your application.

---

## Installation

```bash
npm install @obsidianasecmx/obsidiana-server
```

On first `listen()`, the server generates a persistent ECDSA P-256 identity keypair and saves it under `.obsidiana/` in your working directory. Add this directory to `.gitignore` — never commit the private key.

```
.obsidiana/
  server.key   ← Private key (JWK format — keep secret)
  server.pub   ← Public key (base64 — embed in your client)
```

### Client bundles

If `@obsidianasecmx/obsidiana-client` is installed, the server automatically builds four pre-configured client bundles on every boot and copies them to `.obsidiana/`. Each bundle has the server's public key hardcoded into it so clients can verify the server's identity without any extra configuration.

```
.obsidiana/
  obsidiana-client.js      ← ES module  — React / React Native
  obsidiana-client.min.js  ← ES module (minified) — React / React Native (production)
  obsidiana-client.umd.js  ← UMD bundle — browsers (script tag)
  obsidiana-client.node.js ← CommonJS   — Node.js server-to-server
```

**React / React Native** — use the ES module build:

```jsx
import ObsidianaClient from "./obsidiana-client.js";
// or the minified build for production:
// import ObsidianaClient from './obsidiana-client.min.js'

const { createClient, createWSClient } = ObsidianaClient;
```

**Browser** — load the UMD bundle via a `<script>` tag:

```html
<script src="/obsidiana-client.umd.js"></script>
<script>
  const { createClient, createWSClient } = ObsidianaClient;
</script>
```

**Node.js** — use the CommonJS build:

```js
const { createClient, createWSClient } = require("./obsidiana-client.node.js");
```

---

## Quick Start

```js
const { createObsidiana } = require("@obsidianasecmx/obsidiana-server");

const app = createObsidiana();

// Encrypted route — req.body is already decrypted
app.post("/api/echo", (req, res) => {
  res.json(200, { received: req.body });
});

// Public route — plaintext, no encryption
app.public.get("/health", (req, res) => {
  res.json(200, { status: "ok" });
});

app.listen(3000).then(({ port }) => {
  console.log(`Listening on port ${port}`);
});
```

---

## Server Configuration

```js
const app = createObsidiana({
  // Maximum request body size in bytes (default: 512 KB)
  maxBodySize: 1024 * 1024,

  // Proof-of-Work options
  pow: {
    min: 2, // Minimum difficulty — leading zero bits (default: 2)
    max: 8, // Maximum difficulty under load (default: 8)
    window: 10, // Seconds window to measure request rate (default: 10)
    challengeTTL: 30, // Seconds before a challenge expires (default: 30)
  },

  // Rate limiting (applied per IP + method + path)
  rateLimit: {
    enabled: true, // Set to false to disable (default: enabled)
    windowMs: 60000, // Time window in milliseconds (default: 60000)
    max: 100, // Max requests per window (default: 100)
    message: "Too many requests",
  },

  // Authentication helpers
  auth: {
    cookies: {
      secure: true, // HTTPS only (default: true)
      httpOnly: true, // Inaccessible from JavaScript (default: true)
      sameSite: "Strict", // SameSite policy (default: "Strict")
      defaultMaxAge: 2592000, // TTL in seconds — 30 days (default: 2592000)
      signCookies: true, // ECDSA-sign each cookie (default: true)
    },
    tokens: {
      defaultTTL: 604800, // Token TTL in seconds — 7 days (default: 604800)
    },
  },
});
```

---

## Routing

### Encrypted routes (default)

Routes registered directly on `app` are **encrypted**. The crypto middleware decrypts `req.body` before your handler runs and encrypts the response when you call `res.json()`, `res.send()`, or `res.text()`. Clients must complete the handshake before accessing these routes.

```js
app.get("/api/profile", (req, res) => {
  /* ... */
});
app.post("/api/messages", (req, res) => {
  /* ... */
});
app.put("/api/users/:id", (req, res) => {
  /* ... */
});
app.patch("/api/items/:id", (req, res) => {
  /* ... */
});
app.delete("/api/posts/:id", (req, res) => {
  /* ... */
});
```

You can also use `app.on(method, path, handler)` directly:

```js
app.on("GET", "/api/data", handler);
```

### Public routes (no encryption)

Routes registered under `app.public` skip the crypto middleware entirely. Request bodies are parsed as plain JSON. Use these for health checks, public APIs, or any endpoint that does not require confidentiality.

```js
app.public.get("/health", (req, res) => res.json(200, { status: "ok" }));
app.public.get("/api/open", (req, res) => res.json(200, { data: "public" }));
app.public.post("/api/feedback", (req, res) => res.json(201, { ok: true }));
```

### Route parameters

Use `:param` for named segments and `*` for wildcards:

```js
app.get("/users/:id", (req, res) => {
  const { id } = req.params;
  res.json(200, { userId: id });
});

app.get("/files/*", (req, res) => {
  const filePath = req.params[0]; // wildcard capture
  res.json(200, { path: filePath });
});
```

If the path exists but the method doesn't match, the server responds with `405`. Unknown paths return `404`.

---

## Request & Response

### Request (`req`)

The raw Node.js `IncomingMessage` is extended with:

| Property              | Type                                     | Description                            |
| --------------------- | ---------------------------------------- | -------------------------------------- |
| `req.body`            | `any`                                    | Decrypted and parsed request body      |
| `req.params`          | `Record<string, string>`                 | Named route parameters                 |
| `req.query`           | `URLSearchParams`                        | Parsed query string                    |
| `req.pathname`        | `string`                                 | URL path without query string          |
| `req.isAuthenticated` | `boolean`                                | `true` if a valid credential was found |
| `req.user`            | `object \| null`                         | Authenticated user payload             |
| `req.authMethod`      | `"cookie" \| "bearer" \| "body" \| null` | How the user authenticated             |
| `req.rawBody(limit?)` | `() => Promise<Uint8Array>`              | Reads and buffers the raw request body |
| `req.getCookie(name)` | `(name: string) => Promise<any>`         | Reads and decrypts a named cookie      |

```js
app.post("/api/users", (req, res) => {
  const { name, email } = req.body;
  const page = req.query.get("page") ?? "1";
  res.json(201, { id: "abc", name, email });
});
```

### Response (`res`)

The raw `ServerResponse` is extended with:

| Method                              | Description                                                                                  |
| ----------------------------------- | -------------------------------------------------------------------------------------------- |
| `res.json(status, data, headers?)`  | Sends JSON (encrypted on private routes)                                                     |
| `res.send(status, body, headers?)`  | Auto-detects content type: `Uint8Array` → `octet-stream`, object → JSON, string → plain text |
| `res.html(status, html, headers?)`  | Sends HTML                                                                                   |
| `res.setCookie(name, value, opts?)` | Encrypts and sets a cookie (`__Secure-obs-` prefixed)                                        |
| `res.removeCookie(name)`            | Clears a cookie by setting `Max-Age=0`                                                       |
| `res.createToken(payload, ttl?)`    | Generates an AES-GCM + ECDSA-signed stateless token                                          |

All responses automatically include `X-Powered-By: obsidiana-server` and `X-Obsidiana-Protocol: obsidiana-v1`.

If a handler returns without calling any response method, the server automatically sends `204 No Content`.

---

## WebSocket

Enable WebSocket support by passing `{ ws: true }` to `listen()`, then register handlers with `app.ws(path, handler)`.

Each WebSocket connection runs the full PoW + ECDH handshake immediately after the upgrade. The handler is only called once the handshake completes. After that, `socket.send()` automatically encrypts outgoing messages and `socket.on("obsidiana:message", handler)` delivers decrypted incoming messages.

```js
const app = createObsidiana();

app.ws("/chat", (socket, req) => {
  console.log("Client connected");

  socket.on("obsidiana:message", (data) => {
    console.log("Received:", data);
    socket.send({ echo: data }); // automatically encrypted
  });

  socket.on("close", () => {
    console.log("Client disconnected");
  });
});

app.listen(3000, { ws: true });
```

Supported socket events:

| Event               | Description               |
| ------------------- | ------------------------- |
| `obsidiana:message` | Decrypted message payload |
| `close`             | Connection closed         |
| `error`             | Socket error              |

The WebSocket implementation has no external dependencies — frames are encoded and decoded from raw TCP per RFC 6455. Supported opcodes: `text`, `binary`, `ping/pong`, `close`. Maximum message size: 1 MB. Handshake timeout: 30 seconds.

---

## Middleware

### Built-in middleware

All built-in middleware is available under the `middleware` export:

```js
const { middleware } = require("@obsidianasecmx/obsidiana-server");
```

#### `middleware.cors(options?)`

Adds `Access-Control-*` headers and handles `OPTIONS` preflight requests (returns `204`).

```js
app.use(
  middleware.cors({
    origin: "https://example.com", // default: "*"
    methods: "GET,POST,PUT,PATCH,DELETE,OPTIONS", // default
    headers: "Content-Type,Authorization", // default
  }),
);
```

#### `middleware.logger()`

Logs each request to stdout when the response finishes:

```
POST /api/echo 200 12ms
```

```js
app.use(middleware.logger());
```

#### `middleware.securityHeaders(options?)`

Adds: `X-XSS-Protection`, `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Strict-Transport-Security`, `Content-Security-Policy`, and `Permissions-Policy`.

```js
app.use(
  middleware.securityHeaders({
    hsts: true, // default: true
    hstsMaxAge: 31536000, // default: 1 year
    csp: true, // default: true
  }),
);
```

> `securityHeaders()` and `rateLimit()` are applied automatically by the server during `listen()`. You only need to call them manually if you want to customise their options before the server's automatic setup.

#### `middleware.rateLimit(options?)`

In-memory sliding window rate limiter, keyed by `IP + method + path`. Expired entries are cleaned every 60 seconds.

```js
app.use(
  middleware.rateLimit({
    windowMs: 60000, // default: 60 seconds
    max: 100, // default: 100 requests
    message: "Too many requests",
  }),
);
```

Responds with `429` when the limit is exceeded.

### Custom middleware

Middleware functions receive `(req, res, next)` and must call `next()` to continue. Async functions are fully supported.

```js
app.use(async (req, res, next) => {
  console.log(`[${req.method}] ${req.pathname}`);
  await next();
});
```

---

## Authentication

Obsidiana Server includes a unified auth middleware that resolves a user identity from three sources in order:

1. **`auth` cookie** — the `__Secure-obs-auth` encrypted cookie (browser clients)
2. **`Authorization: Bearer <token>`** header (API clients)
3. **`req.body.token`** field (mobile apps)

After resolution, every request has:

```js
req.isAuthenticated; // boolean
req.user; // decrypted payload object or null
req.authMethod; // "cookie" | "bearer" | "body" | null
```

### Encrypted cookies

Cookies are AES-GCM-256 encrypted and optionally ECDSA-signed. The encryption key is derived from the server's identity private key via HKDF, so cookies survive server restarts.

Cookie format on the wire: `__Secure-obs-<name>=v1:<base64url(iv+ciphertext)>:<base64url(signature)>`

```js
// Set a cookie
app.post("/login", async (req, res) => {
  const user = await validateCredentials(req.body);
  await res.setCookie("auth", { userId: user.id, role: user.role });
  res.json(200, { ok: true });
});

// Read a cookie
app.get("/api/me", async (req, res) => {
  const session = await req.getCookie("auth");
  res.json(200, session);
});

// Remove a cookie
app.post("/logout", (req, res) => {
  res.removeCookie("auth");
  res.json(200, { ok: true });
});
```

Cookie options (passed as third argument to `res.setCookie`):

| Option     | Default    | Description                    |
| ---------- | ---------- | ------------------------------ |
| `maxAge`   | `2592000`  | TTL in seconds (30 days)       |
| `path`     | `"/"`      | Cookie path                    |
| `domain`   | —          | Cookie domain                  |
| `httpOnly` | `true`     | Not accessible from JavaScript |
| `secure`   | `true`     | HTTPS only                     |
| `sameSite` | `"Strict"` | SameSite policy                |

### Stateless tokens

Tokens are AES-GCM-256 encrypted and ECDSA-signed. They embed `iat`, `exp`, and a random `jti`.

Token format: `v1:<base64url(iv+ciphertext)>:<base64url(signature)>`

```js
// Issue a token
app.post("/login", async (req, res) => {
  const user = await validateCredentials(req.body);
  const token = await res.createToken({ userId: user.id }, 3600); // 1-hour TTL
  res.json(200, { token });
});

// Client sends on subsequent requests:
// Authorization: Bearer <token>
// The auth middleware verifies and decrypts it automatically.
```

Tokens can be revoked by JTI using the internal `ObsidianaTokenManager.revoke(jti)` method. Revoked JTIs are held in memory until their natural expiration.

### requireAuth / optionalAuth

```js
const {
  requireAuth,
  optionalAuth,
} = require("@obsidianasecmx/obsidiana-server");

// Returns 401 if req.isAuthenticated is false
app.get(
  "/api/profile",
  requireAuth(async (req, res) => {
    res.json(200, { user: req.user });
  }),
);

// Passes through regardless; req.user may be null
app.get(
  "/api/feed",
  optionalAuth(async (req, res) => {
    res.json(200, { personalized: !!req.user });
  }),
);
```

---

## Static Files

```js
const { serveStatic } = require("@obsidianasecmx/obsidiana-server");

app.use(
  serveStatic("./public", {
    spa: false, // Serve index.html on 404 (SPA mode) — default: false
    index: "index.html", // Directory index file — default: "index.html"
    maxAge: 3600, // Cache-Control max-age in seconds — default: 3600
    etag: true, // ETag + 304 responses — default: true
    lastModified: true, // Last-Modified header — default: true
  }),
);
```

Features:

- **MIME type detection** for 25+ extensions
- **ETag + Last-Modified** — returns `304 Not Modified` when the client's cache is fresh
- **Range requests** — returns `206 Partial Content` for streaming/resumable downloads
- **SPA fallback** — serves `index.html` on any unmatched path when `spa: true`
- **Path traversal protection** — paths are normalized and confined to the root directory
- **Forbidden paths** — requests to `.env`, `.git`, `.obsidiana`, `node_modules`, `package.json`, `server.key`, and `server.pub` always return `403`

The static middleware checks the router first — if a registered route matches the path, the middleware is skipped and the route handler runs instead.

---

## Proof-of-Work (PoW)

PoW prevents handshake flooding by requiring clients to perform a small computational task before establishing a session. Difficulty scales dynamically with the current request rate.

**Challenge lifecycle:**

1. Client requests a challenge via `GET /q`. The server returns a random hash + difficulty level, signed with the server identity key. Challenges expire after `challengeTTL` seconds.
2. Client finds a `nonce` such that `SHA-256(hash + nonce)` has `difficulty` leading zero bits. The client also signs the challenge blob with its own ECDSA key.
3. Client sends the solution, its ECDH public key, and a SHA-256 hash of the expected server public key in `POST /q`. The server verifies the PoW solution, the ECDSA signature, and the server key hash. An invalid nonce **deletes the challenge** — only one attempt is allowed.

```js
const app = createObsidiana({
  pow: {
    min: 2, // ~4 SHA-256 attempts at idle
    max: 8, // ~256 SHA-256 attempts under heavy load
    window: 10, // Rate measured over last 10 seconds
    challengeTTL: 30, // Challenge expires after 30 seconds
  },
});
```

Difficulty formula:

```
difficulty = round(min + clamp(requestsInWindow / 20, 0, 1) * (max - min))
```

The challenge blob binary format:  
`id (32 bytes) | difficulty (1 byte) | ttl (2 bytes) | hash (64 bytes)` → base64

---

## Session Management

Sessions are stored in memory with a **2-hour TTL**. Key design decisions:

- **Session IDs are never transmitted.** A 16-character HMAC-derived "static hint" (`aad.hs`) is embedded in every encrypted message. The server uses this hint to look up the session without exposing the real session ID on the wire.
- **Replay protection via nonce registry.** Every message nonce is registered permanently in a `Map`. Reused nonces are rejected with `401`. The registry holds up to 50,000 entries with FIFO eviction.
- **Automatic garbage collection** runs every 5 minutes, removing sessions older than 2 hours.
- **Optional ratchet encryption.** If a `DoubleRatchet` instance is provided during handshake, the session uses forward-secret ratchet encryption on top of the base AES-GCM session.

> Sessions are **ephemeral** — they are lost on server restart. Clients must re-run the handshake to establish a new session.

---

## Server Identity

On first boot, Obsidiana Server generates a persistent **ECDSA P-256** keypair stored in `.obsidiana/`:

```
.obsidiana/
  server.key   ← Private key (JWK format — never share this)
  server.pub   ← Public key (base64 uncompressed P-256 point)
```

The identity keypair is used for:

- **Signing PoW challenges** — clients verify the signature to confirm the server's authenticity before investing CPU.
- **Verifying client offers** — clients sign the challenge blob with their own ECDSA key; the server verifies this during `POST /q`.
- **Server key hash pinning** — clients include a SHA-256 hash of the expected server public key in their offer; the server rejects mismatches.
- **Deriving cookie encryption keys** — via HKDF from the private key (`salt: "obsidiana-cookie-v2"`), making cookies valid across restarts.
- **Deriving token encryption keys** — via HKDF from the private key (`salt: "obsidiana-token-v2"`).
- **Signing cookies** — each encrypted cookie carries an ECDSA signature to detect tampering.
- **Signing tokens** — each token is ECDSA-signed before being issued.
- **Building client bundles** — on every boot, if `obsidiana-client` is present, four bundles are generated with the server public key baked in and written to `.obsidiana/` (see [Client bundles](#client-bundles)).

---

## Security Model

| Threat                     | Mitigation                                                                   |
| -------------------------- | ---------------------------------------------------------------------------- |
| Passive eavesdropping      | AES-GCM-256 per session, key established via ECDH                            |
| MITM on handshake          | Server identity ECDSA signature on every PoW challenge                       |
| Wrong server (key pinning) | Client embeds SHA-256 of server public key; server rejects mismatches        |
| Handshake flooding         | Dynamic PoW — difficulty scales linearly with request rate                   |
| Message tampering          | GCM authentication tag on every message                                      |
| Replay attacks             | Per-message nonce in AAD + permanent nonce registry (50k cap, FIFO eviction) |
| Session confusion          | HMAC-derived static hints — real session ID never leaves the server          |
| PoW brute-force            | Invalid nonce deletes the challenge — one attempt per challenge              |
| Client impersonation       | Client ECDSA-signs the challenge blob during handshake                       |
| Path traversal             | Static paths normalized + forbidden prefix list                              |
| XSS / Clickjacking         | `securityHeaders()` applied automatically (CSP, X-Frame-Options, HSTS)       |
| Rate abuse                 | Built-in rate limiter per IP + method + path                                 |
| Cookie theft               | `HttpOnly` + `Secure` + `SameSite=Strict` by default                         |
| Cookie tampering           | AES-GCM-256 encryption + ECDSA signature per cookie                          |
| Token forgery              | AES-GCM-256 encryption + ECDSA signature + `exp` + `jti`                     |
| Body size abuse            | 512 KB limit on encrypted routes; 64 KB limit on handshake endpoint          |
| WebSocket flooding         | 1 MB per-message limit + 30-second handshake timeout                         |

### Known limitations

- **No mutual client authentication by default.** PoW proves the client did computational work, not who they are. For identity binding, issue a signed token after login and include it in subsequent requests.
- **Ephemeral sessions.** Sessions live in memory and are lost on restart. For production, replace the in-memory store with a Redis-backed implementation.
- **Single-process only.** The in-memory session store does not share state across processes. Multi-instance deployments require sticky sessions or an external shared store.

---

## Internal Architecture

```
createObsidiana(options)
      │
      └── new Server(options)
              │
              ├── MiddlewarePipeline     — sequential middleware execution
              ├── Router                 — method + path matching, :params, * wildcards
              ├── ObsidianaWS            — WebSocket upgrade, PoW + ECDH per socket
              ├── ObsidianaSessionStore  — in-memory sessions (2h TTL) + nonce registry
              ├── ObsidianaPOW           — dynamic challenge generation + SHA-256 verification
              ├── ObsidianaIdentity      — persistent ECDSA P-256 keypair (disk)
              │
              └── _ensureInit() — called once on first listen()
                      │
                      ├── ObsidianaCookieManager  — HKDF-derived AES key, AES-GCM + ECDSA
                      ├── ObsidianaTokenManager   — HKDF-derived AES key, AES-GCM + ECDSA
                      ├── securityHeaders()        — auto-applied
                      ├── rateLimit()              — auto-applied
                      ├── obsidianaCrypto()        — decrypt req body / encrypt res body
                      ├── createAuthMiddleware()   — populate req.user from cookie/bearer/body
                      ├── registerProtocol()       — registers GET /q and POST /q
                      ├── ObsidianaWS.init()
                      └── _buildClient()           — builds obsidiana-client bundle if present
```

### Request lifecycle (encrypted route)

```
Incoming HTTP request
    │
    ├── wrapRequest()          — adds query, pathname, params, rawBody(), getCookie()
    ├── wrapResponse()         — adds send(), json(), html(), setCookie(), createToken()
    │
    └── MiddlewarePipeline.run()
            ├── securityHeaders()
            ├── rateLimit()
            ├── obsidianaCrypto()
            │     ├── Route exists? Public? Bypass path? → skip if so
            │     ├── Read raw CBOR body (or _d query param for encrypted GETs)
            │     ├── Decode CBOR envelope → extract AAD → resolve session via static hint
            │     ├── Decrypt body (AES-GCM or ratchet)
            │     ├── Claim nonce → reject replay with 401
            │     └── Wrap res.json/send/html with encryptAndSend()
            └── authMiddleware()
                  ├── Try __Secure-obs-auth cookie
                  ├── Try Authorization: Bearer <token>
                  ├── Try req.body.token
                  └── Set req.user, req.isAuthenticated, req.authMethod

    └── Router.match()         — find handler, populate req.params
    └── handler(req, res)
            └── res.json(200, data)
                    └── encryptAndSend()
                            └── cipher.encrypt(data, { sessionId })
                                    └── CBOR encode → write to socket
```

---

## API Reference

### `createObsidiana(options?)`

```
createObsidiana(options?)  →  Server

options.maxBodySize?                 number   — max body bytes (default: 524288)
options.pow.min?                     number   — min PoW difficulty (default: 2)
options.pow.max?                     number   — max PoW difficulty (default: 8)
options.pow.window?                  number   — rate window in seconds (default: 10)
options.pow.challengeTTL?            number   — challenge TTL in seconds (default: 30)
options.rateLimit.enabled?           boolean  — disable rate limiting (default: true)
options.rateLimit.windowMs?          number   — window in ms (default: 60000)
options.rateLimit.max?               number   — max requests per window (default: 100)
options.rateLimit.message?           string   — 429 message
options.auth.cookies.secure?         boolean  — (default: true)
options.auth.cookies.httpOnly?       boolean  — (default: true)
options.auth.cookies.sameSite?       string   — (default: "Strict")
options.auth.cookies.defaultMaxAge?  number   — seconds (default: 2592000)
options.auth.cookies.signCookies?    boolean  — (default: true)
options.auth.tokens.defaultTTL?      number   — seconds (default: 604800)
```

### `Server`

```js
// Encrypted route registration
app.get(path, handler)
app.post(path, handler)
app.put(path, handler)
app.patch(path, handler)
app.delete(path, handler)
app.head(path, handler)
app.options(path, handler)
app.on(method, path, handler)    // generic

// Public (plaintext) route registration
app.public.get(path, handler)
app.public.post(path, handler)
app.public.put(path, handler)
app.public.patch(path, handler)
app.public.delete(path, handler)
app.public.head(path, handler)
app.public.options(path, handler)

// Middleware
app.use(...fns)

// WebSocket
app.ws(path, (socket, req) => void)

// Lifecycle
app.listen(port?, options?)  →  Promise<{ port, host, ws }>
  options.ws?     boolean  — enable WebSocket support (default: false)
  options.host?   string   — bind address (default: "0.0.0.0")

app.close()  →  Promise<void>
```

### `middleware`

```js
const { middleware } = require("@obsidianasecmx/obsidiana-server");

middleware.cors({ origin?, methods?, headers? })
middleware.logger()
middleware.securityHeaders({ hsts?, hstsMaxAge?, csp? })
middleware.rateLimit({ windowMs?, max?, message? })
```

### `serveStatic(root, options?)`

```js
const { serveStatic } = require("@obsidianasecmx/obsidiana-server");

serveStatic(root, {
  spa?,           // boolean — SPA fallback (default: false)
  index?,         // string  — index file name (default: "index.html")
  maxAge?,        // number  — Cache-Control max-age seconds (default: 3600)
  etag?,          // boolean — (default: true)
  lastModified?,  // boolean — (default: true)
})
```

### `requireAuth(handler)` / `optionalAuth(handler)`

```js
const {
  requireAuth,
  optionalAuth,
} = require("@obsidianasecmx/obsidiana-server");

requireAuth(handler); // returns 401 if req.isAuthenticated === false
optionalAuth(handler); // always runs; req.user may be null
```

### `req` additions

```
req.body                  any                              — decrypted request body
req.params                Record<string, string>           — route parameters
req.query                 URLSearchParams                  — parsed query string
req.pathname              string                           — URL path
req.isAuthenticated       boolean
req.user                  object | null
req.authMethod            "cookie" | "bearer" | "body" | null
req.rawBody(limit?)       () => Promise<Uint8Array>
req.getCookie(name)       (name: string) => Promise<any>
```

### `res` additions

```
res.json(status, data, headers?)
res.send(status, body, headers?)
res.html(status, html, headers?)
res.setCookie(name, value, options?)   →  Promise<void>
res.removeCookie(name)
res.createToken(payload, ttl?)         →  Promise<string>
```

---

## License

GPL-3.0 — see [LICENSE](./LICENSE).
