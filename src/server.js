"use strict";

/**
 * Core HTTP/WebSocket server class.
 *
 * Handles routing, middleware, WebSocket upgrades, session management,
 * Proof‑of‑Work challenges, and transparent encryption.
 *
 * Routes are encrypted by default unless registered under `app.public`.
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

const DEFAULT_MAX_BODY = 512 * 1024;
const CLIENT_BUILD_PATH =
  require.resolve("@obsidianasecmx/obsidiana-client/build.js");

/**
 * Obsidiana server.
 */
class Server {
  /**
   * @param {object} [options] - Server configuration
   * @param {number} [options.maxBodySize=524288]
   * @param {object} [options.pow] - PoW options
   * @param {object} [options.auth] - Authentication options
   * @param {object} [options.rateLimit] - Rate limiting options
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
   * Adds middleware to the pipeline.
   *
   * @param {...Function} fns - Middleware functions
   * @returns {this}
   */
  use(...fns) {
    this._pipeline.use(...fns);
    return this;
  }

  /**
   * Registers a route for a specific HTTP method.
   *
   * @param {string} method - HTTP method
   * @param {string} path - Route path
   * @param {Function} handler - Handler function
   * @returns {this}
   */
  on(method, path, handler) {
    this._router.on(method, path, handler, false);
    return this;
  }

  /**
   * Registers a WebSocket route.
   *
   * @param {string} path - WebSocket endpoint
   * @param {Function} handler - (socket, req) => void
   * @returns {this}
   */
  ws(path, handler) {
    this._ws.register(path, handler);
    return this;
  }

  /**
   * Starts the server.
   *
   * @param {number} [port=3000] - Listening port
   * @param {object|string} [options] - Options object or host string
   * @param {boolean} [options.ws=false] - Enable WebSocket support
   * @param {string} [options.host="0.0.0.0"] - Hostname
   * @returns {Promise<{port: number, host: string, ws: boolean}>}
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
   * Closes the server.
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
   * Ensures all asynchronous initialisation is done.
   *
   * @private
   * @returns {Promise<void>}
   */
  async _ensureInit() {
    if (!this._initPromise) {
      this._initPromise = (async () => {
        await this._identity.init();

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

        this._pipeline.use(securityHeaders());

        if (this._rateLimitOptions.enabled !== false) {
          this._pipeline.use(rateLimit(this._rateLimitOptions));
        }

        this._pipeline.use(
          obsidianaCrypto(this._store, [HTTP_HANDSHAKE_PATH], this._router),
        );

        this._pipeline.use(
          createAuthMiddleware(this._cookieManager, this._tokenManager),
        );

        registerProtocol(this, this._store, this._pow, this._identity);
        this._ws.init(this._store, this._pow, this._identity);

        await this._buildClient();
      })();
    }
    return this._initPromise;
  }

  /**
   * Builds the obsidiana‑client bundle with the server’s public key.
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
   * @param {http.IncomingMessage} rawReq
   * @param {http.ServerResponse} rawRes
   */
  async _handle(rawReq, rawRes) {
    const baseUrl = `http://${rawReq.headers.host ?? "localhost"}`;
    const req = wrapRequest(rawReq, baseUrl, {
      maxBodySize: this._maxBodySize,
    });
    const res = wrapResponse(rawRes);

    req._serverRouter = this._router;

    if (this._cookieManager) {
      req.getCookie = (name) => this._cookieManager.get(req, name);
      res.setCookie = (name, value, options) =>
        this._cookieManager.set(res, name, value, options);
      res.removeCookie = (name) => this._cookieManager.remove(res, name);
    }

    if (this._tokenManager) {
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
        res.send(pathExists ? 405 : 404);
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

module.exports = { Server };
