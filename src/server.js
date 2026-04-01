"use strict";

/**
 * Obsidiana Server — Core HTTP/WebSocket server class.
 *
 * This class handles all server functionality: HTTP routing, middleware,
 * WebSocket upgrades, session management, Proof-of-Work challenges,
 * and transparent encryption via obsidiana-protocol.
 *
 * @module obsidiana-server/src/server
 * @private
 */

const http = require("http");
const path = require("path");
const fs = require("fs");
const { Router } = require("./router");
const { MiddlewarePipeline } = require("./middleware");
const { wrapRequest } = require("./request");
const { wrapResponse } = require("./response");
const { ObsidianaWS } = require("./ws");
const { ObsidianaSessionStore } = require("./session");
const { ObsidianaPOW } = require("./pow");
const { obsidianaCrypto } = require("./crypto");
const { ObsidianaIdentity } = require("./identity");
const { registerProtocol, HTTP_HANDSHAKE_PATH } = require("./protocol");
const { securityHeaders, rateLimit } = require("./builtins");

/**
 * Default maximum body size for incoming requests (512 KB).
 * @private
 * @constant {number}
 */
const DEFAULT_MAX_BODY = 512 * 1024;

/**
 * Path to obsidiana-client build script — sibling directory.
 * @private
 * @constant {string}
 */
const CLIENT_BUILD_PATH = require.resolve("@obsidianasecmx/obsidiana-client/build.js");

/**
 * Main Obsidiana server class.
 *
 * Creates an HTTP/WebSocket server with automatic end-to-end encryption.
 * Routes are encrypted by default unless registered under `app.public`.
 *
 * @example
 * const app = new Server();
 * await app._ensureInit(); // internal, called by listen()
 * app.get('/api/data', (req, res) => res.json(200, { ok: true }));
 * await app.listen(3000);
 */
class Server {
  /**
   * Creates a new Obsidiana server instance.
   *
   * @param {object} [options] - Server configuration
   * @param {number} [options.maxBodySize=524288] - Maximum request body size in bytes
   * @param {object} [options.pow] - Proof-of-Work configuration (see ObsidianaPOW)
   * @param {object} [options.auth] - Authentication configuration
   * @param {object} [options.auth.cookies] - Cookie manager options
   * @param {object} [options.auth.tokens] - Token manager options
   * @param {object} [options.rateLimit] - Rate limiting configuration
   * @param {number} [options.rateLimit.windowMs=60000] - Time window in milliseconds
   * @param {number} [options.rateLimit.max=100] - Maximum requests per window
   */
  constructor(options = {}) {
    /** @private {MiddlewarePipeline} */
    this._pipeline = new MiddlewarePipeline();

    /** @private {Router} */
    this._router = new Router();

    /** @private {ObsidianaWS} */
    this._ws = new ObsidianaWS();

    /** @private {http.Server|null} */
    this._server = null;

    /** @private {number} */
    this._maxBodySize = options.maxBodySize ?? DEFAULT_MAX_BODY;

    /** @private {ObsidianaSessionStore} */
    this._store = new ObsidianaSessionStore();

    /** @private {ObsidianaPOW} */
    this._pow = new ObsidianaPOW(options.pow ?? {});

    /** @private {ObsidianaIdentity} */
    this._identity = new ObsidianaIdentity();

    /** @private {Promise<void>|null} */
    this._initPromise = null;

    /** @private {ObsidianaCookieManager|null} */
    this._cookieManager = null;

    /** @private {ObsidianaTokenManager|null} */
    this._tokenManager = null;

    /** @private {object} */
    this._authOptions = options.auth || {};

    /** @private {object} */
    this._rateLimitOptions = options.rateLimit || {};

    // Register encrypted route methods
    for (const verb of [
      "get",
      "post",
      "put",
      "patch",
      "delete",
      "head",
      "options",
    ]) {
      this[verb] = (path, handler) => {
        this._router.on(verb.toUpperCase(), path, handler, false);
        return this;
      };
    }

    // Register public (unencrypted) route methods
    this.public = {};
    for (const verb of [
      "get",
      "post",
      "put",
      "patch",
      "delete",
      "head",
      "options",
    ]) {
      this.public[verb] = (path, handler) => {
        this._router.on(verb.toUpperCase(), path, handler, true);
        return this;
      };
    }
  }

  /**
   * Adds middleware to the request pipeline.
   *
   * @param {...Function} fns - Middleware functions
   * @returns {this} Current instance for method chaining
   */
  use(...fns) {
    this._pipeline.use(...fns);
    return this;
  }

  /**
   * Registers a route handler for a specific HTTP method.
   *
   * @param {string} method - HTTP method (GET, POST, etc.)
   * @param {string} path - Route path (supports parameters like /users/:id)
   * @param {Function} handler - Request handler function
   * @returns {this} Current instance for method chaining
   */
  on(method, path, handler) {
    this._router.on(method, path, handler, false);
    return this;
  }

  /**
   * Registers a WebSocket route handler.
   *
   * @param {string} path - WebSocket endpoint path
   * @param {Function} handler - Handler function receiving (socket, req)
   * @returns {this} Current instance for method chaining
   */
  ws(path, handler) {
    this._ws.register(path, handler);
    return this;
  }

  /**
   * Starts the HTTP/WebSocket server.
   *
   * Initializes all components (identity, session store, POW,
   * crypto middleware, protocol routes, WebSocket handlers) before
   * binding to the specified port.
   *
   * @param {number} [port=3000] - Listening port
   * @param {object|string} [options] - Options object or host string
   * @param {boolean} [options.ws=false] - Enable WebSocket support
   * @param {string} [options.host="0.0.0.0"] - Hostname to bind
   * @returns {Promise<{port: number, host: string, ws: boolean}>} Server info
   */
  async listen(port = 3000, options = {}) {
    if (typeof options === "string") options = { host: options };
    const { ws = false, host = "0.0.0.0" } = options;

    await this._ensureInit();

    return new Promise((resolve, reject) => {
      this._server = http.createServer((rawReq, rawRes) => {
        this._handle(rawReq, rawRes);
      });

      if (ws) {
        this._server.on("upgrade", (req, socket, head) => {
          this._ws.handleUpgrade(req, socket, head);
        });
      }

      this._server.once("error", reject);
      this._server.listen(port, host, () => resolve({ port, host, ws }));
    });
  }

  /**
   * Closes the server gracefully.
   *
   * @returns {Promise<void>}
   */
  close() {
    return new Promise((resolve, reject) => {
      if (!this._server) return resolve();
      this._server.close((err) => (err ? reject(err) : resolve()));
    });
  }

  /**
   * Ensures all asynchronous initialization is complete.
   *
   * Initialization steps:
   * 1. Load or generate persistent identity keypair
   * 2. Initialize cookie and token managers
   * 3. Register security headers, rate limiting, crypto middleware, and protocol routes
   * 4. Initialize WebSocket handler
   * 5. Build obsidiana-client bundles with server identity
   *
   * @private
   * @returns {Promise<void>}
   */
  _ensureInit() {
    if (!this._initPromise) {
      this._initPromise = (async () => {
        // 1. Persistent identity keypair — load or generate from disk
        await this._identity.init();

        // 2. Initialize cookie and token managers
        const { ObsidianaCookieManager } = require("./cookies");
        const { ObsidianaTokenManager } = require("./tokens");
        const { createAuthMiddleware } = require("./auth");

        this._cookieManager = new ObsidianaCookieManager(
          this._identity,
          this._authOptions.cookies || {},
        );
        this._tokenManager = new ObsidianaTokenManager(
          this._identity,
          this._authOptions.tokens || {},
        );

        await this._cookieManager.init();
        await this._tokenManager.init();

        // 3. Security headers (must be early in pipeline)
        this._pipeline.use(securityHeaders());

        // 4. Rate limiting
        if (this._rateLimitOptions.enabled !== false) {
          this._pipeline.use(rateLimit(this._rateLimitOptions));
        }

        // 5. Crypto middleware (decrypts request bodies)
        this._pipeline.use(
          obsidianaCrypto(this._store, [HTTP_HANDSHAKE_PATH], this._router),
        );

        // 6. Auth middleware (after crypto so req.body is available)
        this._pipeline.use(
          createAuthMiddleware(this._cookieManager, this._tokenManager),
        );

        // 7. Protocol routes and WebSocket
        registerProtocol(this, this._store, this._pow, this._identity);
        this._ws.init(this._store, this._pow, this._identity);

        // 8. Build obsidiana-client with server identity key hardcoded
        await this._buildClient();
      })();
    }
    return this._initPromise;
  }

  /**
   * Builds obsidiana-client bundles with the server's identity public key.
   *
   * The generated bundles are placed in the `.obsidiana/` directory.
   * This only runs if obsidiana-client is present as a sibling package.
   *
   * @private
   */
  async _buildClient() {
    if (!fs.existsSync(CLIENT_BUILD_PATH)) {
      console.log(
        "[obsidiana] obsidiana-client not found at sibling path — skipping client build.",
      );
      return;
    }

    try {
      console.log(
        "[obsidiana] Building obsidiana-client with server identity...",
      );

      // esbuild resolves entryPoints relative to cwd — must run from client dir
      const clientDir = path.dirname(CLIENT_BUILD_PATH);
      const prevCwd = process.cwd();
      process.chdir(clientDir);

      const { buildClient } = require(CLIENT_BUILD_PATH);
      await buildClient({
        serverKey: this._identity.publicKey,
        copyTo: path.join(prevCwd, ".obsidiana"),
      });

      process.chdir(prevCwd);
      console.log("[obsidiana] obsidiana-client built successfully.");
    } catch (err) {
      console.error("[obsidiana] Client build failed:", err.message);
    }
  }

  /**
   * Handles an incoming HTTP request.
   *
   * @private
   * @param {http.IncomingMessage} rawReq - Raw Node.js request
   * @param {http.ServerResponse} rawRes - Raw Node.js response
   */
  async _handle(rawReq, rawRes) {
    const baseUrl = `http://${rawReq.headers.host ?? "localhost"}`;
    const req = wrapRequest(rawReq, baseUrl, {
      maxBodySize: this._maxBodySize,
    });
    const res = wrapResponse(rawRes);

    req._serverRouter = this._router;

    // Add cookie helpers
    if (this._cookieManager) {
      /**
       * Gets a decrypted cookie.
       *
       * @param {string} name - Cookie name
       * @returns {Promise<any>} Decrypted value
       */
      req.getCookie = (name) => this._cookieManager.get(req, name);

      /**
       * Sets an encrypted cookie.
       *
       * @param {string} name - Cookie name
       * @param {any} value - Value to encrypt
       * @param {object} [options] - Cookie options
       * @returns {Promise<void>}
       */
      res.setCookie = (name, value, options) =>
        this._cookieManager.set(res, name, value, options);

      /**
       * Removes a cookie.
       *
       * @param {string} name - Cookie name
       */
      res.removeCookie = (name) => this._cookieManager.remove(res, name);
    }

    // Add token helper
    if (this._tokenManager) {
      /**
       * Creates an encrypted token.
       *
       * @param {object} payload - Data to embed
       * @param {number} [ttl] - Time to live in seconds
       * @returns {Promise<string>} Encrypted token
       */
      res.createToken = (payload, ttl) =>
        this._tokenManager.generate(payload, ttl);
    }

    try {
      await this._pipeline.run(req, res);
      if (res.writableEnded) return;

      if (req.pathname.match(/[^a-zA-Z0-9\/\-_.]/)) {
        res.send(400);
        return;
      }

      const match = this._router.match(req.method, req.pathname);
      if (!match) {
        const pathExists = this._router._routes.some((route) =>
          route.regex.test(req.pathname),
        );

        if (pathExists) {
          res.send(405);
        } else {
          res.send(404);
        }

        return;
      }

      req.params = match.params;
      req.routePublic = match.public;

      await match.handler(req, res);

      if (res._obsidianSend) await res._obsidianSend;
      if (!res.writableEnded) res.send(204);
    } catch (err) {
      if (!res.writableEnded) {
        if (err.status === 413) {
          res.send(413);
          return;
        }
        const isDev = process.env.NODE_ENV !== "production";
        res.send(500, isDev ? { message: err.message } : "");
      }
      if (err.status !== 413) {
        console.error("[obsidiana] error:", err.message);
      }
    }
  }
}

/**
 * @exports
 * @property {Class} Server - Main server class
 */
module.exports = { Server };
