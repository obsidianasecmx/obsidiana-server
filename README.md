# Obsidiana Server

A zero-dependency HTTP/WebSocket framework with **transparent end-to-end encryption** built on top of [obsidiana-protocol](https://github.com/obsidianasecmx/obsidiana-protocol). All routes are encrypted by default — request bodies arrive already decrypted to your handlers, and responses are encrypted before leaving the server.

**Requires Node.js 18+. No external dependencies.**

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
  - [Cookies](#cookies)
  - [Tokens](#tokens)
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
Client                                      Server
──────                                      ──────
GET /q  ──────────────────────────────────► Issue PoW challenge (signed with server identity)
        ◄─────────────────────── { challenge, serverSig }

Solve PoW, sign challenge, send ECDH key
POST /q ──── { offer, nonce, clientSig } ──► Verify PoW + signature, complete ECDH
        ◄──────────────────── { response }   Session stored, AES-GCM-256 key derived

All subsequent HTTP requests:
POST /api/data  ──── CBOR({ d: encrypted }) ──► Decrypt → req.body = { ... }
                ◄─── CBOR({ d: encrypted }) ──  res.json(200, data) → encrypted

WebSocket same flow with PoW + ECDH before first message.
```

The handshake endpoint is `/q`. Everything else is an application route.

---

## Installation

```bash
npm install @obsidianasecmx/obsidiana-server
```

> `obsidiana-protocol` is a peer dependency — install it alongside this package.

On first `listen()`, the server generates a persistent ECDSA P-256 identity keypair and saves it to `.obsidiana/` in your working directory. This directory should be **kept out of version control** (add it to `.gitignore`).

```
.obsidiana/
  server.key   ← Private key (JWK, keep secret)
  server.pub   ← Public key (base64, distribute to clients)
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

// Public route — no encryption needed
app.public.get("/health", (req, res) => {
  res.json(200, { status: "ok" });
});

app.listen(3000).then(({ port }) => {
  console.log(`Server running on port ${port}`);
});
```

---

## Server Configuration

```js
const app = createObsidiana({
  // Maximum request body size (default: 512 KB)
  maxBodySize: 1024 * 1024,

  // Proof-of-Work (see PoW section)
  pow: {
    min: 2,           // Minimum difficulty (leading zero bits)
    max: 8,           // Maximum difficulty under load
    window: 10,       // Seconds window to measure request rate
    challengeTTL: 30, // Seconds before a challenge expires
  },

  // Rate limiting
  rateLimit: {
    windowMs: 60000,  // Time window (ms)
    max: 100,         // Max requests per window per IP+endpoint
  },

  // Authentication helpers
  auth: {
    cookies: {
      secure: true,           // HTTPS only
      httpOnly: true,         // Inaccessible from JS
      sameSite: "Strict",     // SameSite policy
      defaultMaxAge: 2592000, // 30 days (seconds)
      signCookies: true,      // Sign with ECDSA
    },
    tokens: {
      defaultTTL: 604800,     // 7 days (seconds)
    },
  },
});
```

---

## Routing

### Encrypted routes (default)

All routes registered directly on `app` are **encrypted**. The crypto middleware automatically decrypts `req.body` before reaching your handler and encrypts the response after `res.json()` / `res.send()` / `res.text()`.

```js
app.get("/api/profile",    (req, res) => { /* ... */ });
app.post("/api/messages",  (req, res) => { /* ... */ });
app.put("/api/users/:id",  (req, res) => { /* ... */ });
app.patch("/api/items/:id",(req, res) => { /* ... */ });
app.delete("/api/posts/:id",(req, res) => { /* ... */ });
```

You can also use `app.on(method, path, handler)` for non-standard verbs:

```js
app.on("GET", "/api/data", handler);
```

### Public routes (no encryption)

Routes registered under `app.public` skip the crypto middleware entirely. Use them for health checks, public APIs, or any endpoint that doesn't need confidentiality.

```js
app.public.get("/health",        (req, res) => res.json(200, { status: "ok" }));
app.public.get("/api/public",    (req, res) => res.json(200, { data: "open" }));
app.public.post("/api/feedback", (req, res) => res.json(201, { ok: true }));
```

### Route parameters

Use `:param` for dynamic segments and `*` for wildcards:

```js
app.get("/users/:id", (req, res) => {
  const { id } = req.params;
  res.json(200, { userId: id });
});

app.get("/files/*", (req, res) => {
  const path = req.params[0]; // wildcard capture
  res.json(200, { path });
});
```

---

## Request & Response

### Request object (`req`)

The raw Node.js `IncomingMessage` is augmented with:

| Property | Type | Description |
|---|---|---|
| `req.body` | `any` | Decrypted and parsed request body |
| `req.params` | `Record<string, string>` | Route parameters from URL |
| `req.query` | `URLSearchParams` | Parsed query string |
| `req.pathname` | `string` | URL path without query string |
| `req.isAuthenticated` | `boolean` | Set by auth middleware |
| `req.user` | `object \| null` | Authenticated user data |
| `req.authMethod` | `string \| null` | `"cookie"`, `"bearer"`, or `"body"` |
| `req.rawBody(limit?)` | `() => Promise<Uint8Array>` | Reads and buffers the raw request body |
| `req.getCookie(name)` | `(name) => Promise<any>` | Reads and decrypts a cookie |

```js
app.post("/api/users", (req, res) => {
  // req.body = { name: "Alice", email: "alice@example.com" }
  const { name, email } = req.body;
  const page = req.query.get("page") ?? "1";
  res.json(201, { id: "abc", name, email });
});
```

### Response object (`res`)

The raw `ServerResponse` is augmented with:

| Method | Description |
|---|---|
| `res.json(status, data)` | Sends JSON (encrypted on private routes) |
| `res.send(status, body)` | Auto-detects content type (Buffer → octet-stream, object → JSON, string → text) |
| `res.html(status, html)` | Sends HTML |
| `res.setCookie(name, value, opts?)` | Sets an AES-GCM encrypted cookie |
| `res.removeCookie(name)` | Clears a cookie |
| `res.createToken(payload, ttl?)` | Creates an encrypted stateless token |

Every response automatically includes `X-Powered-By: obsidiana-server` and `X-Obsidiana-Protocol: obsidiana-v1` headers.

---

## WebSocket

WebSocket connections go through the same PoW + ECDH handshake as HTTP. After the handshake, all messages are AES-GCM-256 encrypted automatically.

```js
const app = createObsidiana();

app.ws("/live", (socket, req) => {
  console.log("Client connected");

  // Receives decrypted data
  socket.on("obsidiana:message", (data) => {
    console.log("Received:", data);
    // Sends encrypted reply
    socket.send({ pong: data });
  });

  socket.on("close", () => {
    console.log("Client disconnected");
  });

  socket.on("error", (err) => {
    console.error("Socket error:", err);
  });
});

// Enable WebSocket support in listen()
app.listen(3000, { ws: true });
```

### WebSocket socket API

| Method / Event | Description |
|---|---|
| `socket.send(data)` | Encrypts and sends any JSON-serializable value |
| `socket.close(code?, reason?)` | Closes the connection (codes per RFC 6455) |
| `socket.on("obsidiana:message", fn)` | Fires with **decrypted** message data |
| `socket.on("close", fn)` | Fires when connection is closed |
| `socket.on("error", fn)` | Fires on socket error |

---

## Middleware

### Built-in middleware

```js
const { createObsidiana, middleware } = require("@obsidianasecmx/obsidiana-server");

const app = createObsidiana();

// Cross-Origin Resource Sharing
app.use(middleware.cors({
  origin: "https://myapp.com",
  methods: "GET,POST,PUT,DELETE",
  headers: "Content-Type,Authorization",
}));

// Request logging → "POST /api/users 201 34ms"
app.use(middleware.logger());

// Security headers (XSS, CSP, HSTS, X-Frame-Options, etc.)
app.use(middleware.securityHeaders({
  hsts: true,
  hstsMaxAge: 31536000,
  csp: true,
}));

// Rate limiting per IP + endpoint
app.use(middleware.rateLimit({
  windowMs: 60000, // 1 minute
  max: 100,        // 100 requests per window
  message: "Too many requests",
}));
```

### Custom middleware

Middleware functions receive `(req, res, next)` — call `next()` to continue or omit it to end the pipeline early.

```js
// Synchronous middleware
app.use((req, res, next) => {
  req.startTime = Date.now();
  next();
});

// Async middleware
app.use(async (req, res, next) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  if (await isBlocked(ip)) {
    return res.send(403);
  }
  next();
});

// Error handling (call next(err) or throw)
app.use((req, res, next) => {
  try {
    // ... something that might throw
    next();
  } catch (err) {
    next(err); // or just throw
  }
});
```

The middleware pipeline runs **before** route handlers. The internal order is:

1. Security headers
2. Rate limiting
3. **Crypto middleware** (decrypts `req.body`)
4. Auth middleware (populates `req.user`)
5. Your `app.use()` middleware
6. Route handler

---

## Authentication

Obsidiana Server includes three authentication strategies, resolved in priority order: **auth cookie → Bearer token → token in body**.

### Cookies

Cookies are AES-GCM-256 encrypted and optionally ECDSA-signed using the server's identity key. They survive server restarts because the encryption key is derived from the persistent identity keypair.

```js
// Set an encrypted cookie
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await authenticate(username, password);
  if (!user) return res.send(401);

  // Encrypted cookie — stored as __Secure-obs-auth
  await res.setCookie("auth", { userId: user.id, role: user.role });
  res.json(200, { ok: true });
});

// Read cookie
app.get("/api/me", async (req, res) => {
  const auth = await req.getCookie("auth");
  if (!auth) return res.send(401);
  res.json(200, { userId: auth.userId, role: auth.role });
});

// Remove cookie
app.post("/api/logout", (req, res) => {
  res.removeCookie("auth");
  res.send(200);
});
```

Cookie options:

```js
await res.setCookie("session", data, {
  maxAge: 86400,       // 1 day in seconds (overrides defaultMaxAge)
  path: "/api",        // Path scope
  domain: ".myapp.com" // Domain scope
});
```

### Tokens

Stateless encrypted tokens for API clients and mobile apps. Token format: `v1:encrypted:signature`. All data lives inside the token — no database needed.

```js
// Generate a token
app.post("/api/auth/token", async (req, res) => {
  const user = await authenticate(req.body);
  if (!user) return res.send(401);

  // Token encrypted + signed with server identity key
  const token = await res.createToken(
    { userId: user.id, role: user.role },
    604800 // TTL in seconds (7 days)
  );
  res.json(200, { token });
});

// Client sends: Authorization: Bearer <token>
// Or: req.body.token = "<token>"
// Auth middleware verifies and sets req.user automatically
```

### requireAuth / optionalAuth

```js
const { requireAuth, optionalAuth } = require("@obsidianasecmx/obsidiana-server");

// Requires authentication — returns 401 if not authenticated
app.get("/api/profile", requireAuth(async (req, res) => {
  // req.user is guaranteed to be set here
  res.json(200, { user: req.user });
}));

// Optional — req.user may or may not be set
app.get("/api/feed", optionalAuth(async (req, res) => {
  if (req.isAuthenticated) {
    res.json(200, { feed: await getPersonalizedFeed(req.user.userId) });
  } else {
    res.json(200, { feed: await getPublicFeed() });
  }
}));
```

---

## Static Files

```js
const { createObsidiana, serveStatic } = require("@obsidianasecmx/obsidiana-server");

const app = createObsidiana();

// Basic static serving
app.use(serveStatic("./public"));

// SPA mode — all unmatched routes serve index.html
app.use(serveStatic("./dist", { spa: true }));

app.listen(3000);
```

Static middleware options:

| Option | Default | Description |
|---|---|---|
| `spa` | `false` | Serve `index.html` for unmatched routes (React, Vue, etc.) |
| `index` | `"index.html"` | Default file for directory requests |
| `maxAge` | `3600` | Cache max age in seconds |
| `etag` | `true` | Enable ETag for conditional requests |
| `lastModified` | `true` | Enable Last-Modified header |

Encrypted API routes always take precedence over static files. The following paths are blocked for security: `.env`, `.git`, `.obsidiana`, `node_modules`, `package.json`, `server.key`.

**Supported features:** MIME detection, ETags, 304 Not Modified, Range requests (partial content), path traversal protection, directory index fallback.

---

## Proof-of-Work (PoW)

The PoW system defends the handshake endpoint against flooding attacks. Before the ECDH key exchange can happen, the client must solve a SHA-256 puzzle.

**How it works:**

1. Client calls `GET /q` — server returns a challenge `{ hash, difficulty, ttl }` signed with its identity key.
2. Client verifies the server's signature (confirms it's talking to the right server).
3. Client finds a `nonce` such that `SHA-256(hash + nonce)` starts with `difficulty` leading zero bits.
4. Client includes the `nonce` and its own ECDSA signature in the `POST /q` offer.
5. Server verifies both the PoW solution and the client signature, then completes ECDH.

**Dynamic difficulty** — difficulty scales linearly from `min` to `max` based on the request rate in the last `window` seconds. At 20 req/window the difficulty is at maximum:

```js
const app = createObsidiana({
  pow: {
    min: 2,           // ~4 SHA-256 attempts at idle
    max: 8,           // ~256 SHA-256 attempts under load
    window: 10,       // Rate measured over 10 seconds
    challengeTTL: 30, // Challenge expires in 30 seconds
  }
});
```

---

## Session Management

Sessions are stored in memory with a 2-hour TTL. Key design decisions:

- **Session IDs are never transmitted.** Instead, a 16-character HMAC-derived "static hint" is embedded in every encrypted message. The server uses this hint to look up the session without exposing the real session ID on the wire.
- **Nonce registry prevents replay attacks.** Every message nonce is permanently registered. Reused nonces are rejected with 401. The registry holds up to 50,000 nonces (FIFO eviction).
- **Automatic garbage collection** runs every 5 minutes, removing sessions older than 2 hours.

> Sessions are **ephemeral** — they are lost on server restart. For persistent sessions, clients must re-establish the handshake.

---

## Server Identity

On first boot, Obsidiana Server generates a persistent ECDSA P-256 keypair and stores it in `.obsidiana/`:

```
.obsidiana/
  server.key   ← Private key (JWK format, never share this)
  server.pub   ← Public key (base64, embed in your client)
```

The identity keypair is used for:
- **Signing PoW challenges** — clients verify this signature to confirm the server's authenticity.
- **Deriving encryption keys** for cookies and tokens (via HKDF from the private key).
- **Cookie signing** — ECDSA signatures on encrypted cookies to detect tampering.

The client must embed the server's public key (from `.obsidiana/server.pub`) to verify the server's identity during handshake. If `obsidiana-client` is installed as a sibling package, Obsidiana Server automatically builds a pre-configured client bundle with the server key hardcoded.

---

## Security Model

| Threat | Mitigation |
|---|---|
| Passive eavesdropping | AES-GCM-256 per session, established via ECDH |
| MITM on handshake | Server identity signature (PoW challenge signed with persistent ECDSA key) |
| Handshake flooding | Dynamic Proof-of-Work (difficulty scales with request rate) |
| Message tampering | GCM authentication tag + ECDSA-signed AAD on every message |
| Replay attacks | Per-message nonce + ±60s timestamp window + permanent nonce registry |
| Session confusion | HMAC-derived session hints — session ID never on the wire |
| Brute-force PoW | Invalid nonce deletes challenge (only one try per challenge) |
| Path traversal | Normalized static paths, forbidden prefix list |
| XSS / Clickjacking | `securityHeaders()` middleware (CSP, X-Frame-Options, HSTS) |
| Rate abuse | Built-in rate limiter per IP + endpoint |
| Cookie theft | HttpOnly + Secure + SameSite=Strict by default |
| Cookie tampering | AES-GCM encryption + ECDSA signature |
| Token forgery | AES-GCM encryption + ECDSA signature + expiration |

### What is not provided

- **Mutual client authentication by default.** The PoW handshake proves the client did work, not who the client is. For identity binding, issue a signed token after login and include it in subsequent handshakes.
- **Persistent sessions.** Sessions live in memory and are lost on restart. For production, replace `ObsidianaSessionStore` with a Redis-backed store.
- **Horizontal scaling.** The in-memory session store does not share state across processes. Use sticky sessions or a shared store for multi-instance deployments.

---

## Internal Architecture

```
createObsidiana(options)
      │
      └── new Server(options)
              │
              ├── MiddlewarePipeline     ← Sequential middleware execution
              ├── Router                 ← Path + method matching, :params, *wildcards
              ├── ObsidianaWS            ← WebSocket upgrade + PoW + ECDH per socket
              ├── ObsidianaSessionStore  ← In-memory sessions + nonce registry
              ├── ObsidianaPOW           ← Dynamic PoW challenges + verification
              ├── ObsidianaIdentity      ← Persistent ECDSA keypair (disk)
              │
              └── _ensureInit() on listen()
                      │
                      ├── ObsidianaCookieManager (derived from identity key)
                      ├── ObsidianaTokenManager  (derived from identity key)
                      ├── securityHeaders()  middleware
                      ├── rateLimit()        middleware
                      ├── obsidianaCrypto()  middleware  ← decrypt req / encrypt res
                      ├── createAuthMiddleware()          ← populate req.user
                      ├── registerProtocol() → GET /q, POST /q
                      └── ObsidianaWS.init()
```

### Request lifecycle (encrypted route)

```
HTTP Request
    │
    ├── wrapRequest()         → adds query, pathname, params, rawBody()
    ├── wrapResponse()        → adds send(), json(), html()
    │
    ├── MiddlewarePipeline.run()
    │       ├── securityHeaders()
    │       ├── rateLimit()
    │       ├── obsidianaCrypto()  → decode CBOR → resolve session → decrypt req.body
    │       │                         wrap res.json/send with encryptAndSend()
    │       └── authMiddleware()   → check cookie/Bearer/body token → req.user
    │
    ├── Router.match()        → find handler, extract params
    └── handler(req, res)
            └── res.json(200, data)
                    └── encryptAndSend() → cipher.encrypt(data) → CBOR → wire
```

---

## API Reference

### `createObsidiana(options?)`

```
createObsidiana(options?)  →  Server instance

options.maxBodySize?       number    — default: 524288 (512 KB)
options.pow?               object    — PoW configuration
options.rateLimit?         object    — Rate limit configuration
options.auth?.cookies?     object    — Cookie manager options
options.auth?.tokens?      object    — Token manager options
```

### `Server`

```
// Route registration (encrypted)
app.get(path, handler)
app.post(path, handler)
app.put(path, handler)
app.patch(path, handler)
app.delete(path, handler)
app.on(method, path, handler)

// Route registration (public)
app.public.get(path, handler)
app.public.post(path, handler)
// ... same methods

// Middleware
app.use(...fns)

// WebSocket
app.ws(path, handler)

// Lifecycle
app.listen(port?, options?)  →  Promise<{ port, host, ws }>
  options.ws?     boolean   — enable WebSocket support (default: false)
  options.host?   string    — bind address (default: "0.0.0.0")
app.close()  →  Promise<void>
```

### `middleware`

```js
const { middleware } = require("@obsidianasecmx/obsidiana-server");

middleware.cors(options?)
  options.origin?   string   — default: "*"
  options.methods?  string   — default: "GET,POST,PUT,PATCH,DELETE,OPTIONS"
  options.headers?  string   — default: "Content-Type,Authorization"

middleware.logger()

middleware.securityHeaders(options?)
  options.hsts?        boolean  — default: true
  options.hstsMaxAge?  number   — default: 31536000
  options.csp?         boolean  — default: true

middleware.rateLimit(options?)
  options.windowMs?  number  — default: 60000
  options.max?       number  — default: 100
  options.message?   string  — default: "Too many requests"
```

### `serveStatic(root, options?)`

```
serveStatic(root, options?)  →  middleware function

options.spa?          boolean  — default: false
options.index?        string   — default: "index.html"
options.maxAge?       number   — default: 3600
options.etag?         boolean  — default: true
options.lastModified? boolean  — default: true
```

### `requireAuth(handler)` / `optionalAuth(handler)`

```
requireAuth(handler)   →  wrapped handler — returns 401 if not authenticated
optionalAuth(handler)  →  wrapped handler — passes through, req.user may be null
```

### `req` additions

```
req.body          any               — decrypted request body
req.params        Record<str,str>   — route parameters
req.query         URLSearchParams   — parsed query string
req.pathname      string            — URL path
req.isAuthenticated  boolean
req.user          object | null
req.authMethod    "cookie" | "bearer" | "body" | null
req.rawBody(limit?)  () => Promise<Uint8Array>
req.getCookie(name)  (name) => Promise<any>
```

### `res` additions

```
res.json(status, data, headers?)
res.send(status, body, headers?)
res.html(status, html, headers?)
res.setCookie(name, value, opts?)    →  Promise<void>
res.removeCookie(name)
res.createToken(payload, ttl?)       →  Promise<string>
```

---

## License

See [LICENSE](./LICENSE).
