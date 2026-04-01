"use strict";

/**
 * Obsidiana Server — HTTP/WebSocket framework with end-to-end encryption.
 *
 * A zero‑dependency server framework built on top of obsidiana-protocol.
 * Provides transparent E2E encryption for HTTP and WebSocket routes,
 * automatic handshake management, dynamic Proof‑of‑Work, session storage,
 * and middleware support.
 *
 * All routes are encrypted by default. The server handles ECDH key exchange,
 * HKDF key derivation, AES‑GCM‑256 encryption, and ECDSA signature
 * verification automatically. Request bodies are decrypted before reaching
 * your handlers, and responses are encrypted before being sent.
 *
 * @module obsidiana-server
 *
 * @example
 * // Basic HTTP server with encrypted routes
 * const { createObsidiana } = require('@obsidianasecmx/obsidiana-server');
 *
 * const app = createObsidiana();
 *
 * app.post('/api/data', (req, res) => {
 *   // req.body is already decrypted
 *   res.json(200, { received: req.body });
 * });
 *
 * app.listen(3000).then(() => console.log('Server running'));
 *
 * @example
 * // WebSocket with encrypted messages
 * const app = createObsidiana();
 *
 * app.ws('/live', (socket, req) => {
 *   socket.on('obsidiana:message', (data) => {
 *     // data is decrypted automatically
 *     socket.send({ pong: data });
 *   });
 * });
 *
 * app.listen(3000, { ws: true });
 *
 * @example
 * // Mixing public and private routes
 * const app = createObsidiana();
 *
 * // Public route – no encryption
 * app.public.get('/health', (req, res) => {
 *   res.json(200, { status: 'ok' });
 * });
 *
 * // Private route – E2E encrypted
 * app.post('/api/users', (req, res) => {
 *   res.json(201, { id: '123', ...req.body });
 * });
 *
 * @example
 * // Using built-in middleware
 * const { middleware } = require('@obsidianasecmx/obsidiana-server');
 *
 * const app = createObsidiana();
 * app.use(middleware.cors());
 * app.use(middleware.logger());
 * app.use(middleware.securityHeaders());
 * app.use(middleware.rateLimit({ max: 100 }));
 *
 * @example
 * // Configure cookies and tokens
 * const app = createObsidiana({
 *   auth: {
 *     cookies: {
 *       secure: true,
 *       httpOnly: true,
 *       sameSite: 'Strict',
 *       defaultMaxAge: 2592000,
 *       signCookies: true
 *     },
 *     tokens: {
 *       defaultTTL: 604800
 *     }
 *   },
 *   rateLimit: {
 *     windowMs: 60000,
 *     max: 100
 *   },
 *   pow: {
 *     min: 2,
 *     max: 8,
 *     window: 10,
 *     challengeTTL: 30
 *   }
 * });
 */

// Core server components
const { Server } = require("./src/server");
const { serveStatic } = require("./src/static");
const { cors, logger, securityHeaders, rateLimit } = require("./src/builtins");
const { requireAuth, optionalAuth } = require("./src/auth");

/**
 * Creates and returns a new Obsidiana server instance.
 *
 * The server is configured with sensible defaults. Encryption, handshake,
 * Proof-of-Work, and session management are automatic. All routes are
 * encrypted unless explicitly marked as public via `app.public`.
 *
 * @param {object} [options] - Server configuration
 * @param {object} [options.pow] - Proof-of-Work configuration
 * @param {number} [options.pow.min=2] - Minimum difficulty (leading zero bits)
 * @param {number} [options.pow.max=8] - Maximum difficulty under load
 * @param {number} [options.pow.window=10] - Time window (seconds) to measure request rate
 * @param {number} [options.pow.challengeTTL=30] - Seconds before a challenge expires
 * @param {object} [options.rateLimit] - Rate limiting configuration
 * @param {number} [options.rateLimit.windowMs=60000] - Time window in milliseconds
 * @param {number} [options.rateLimit.max=100] - Maximum requests per window
 * @param {object} [options.auth] - Authentication configuration
 * @param {object} [options.auth.cookies] - Cookie manager options
 * @param {boolean} [options.auth.cookies.secure=true] - HTTPS only flag
 * @param {boolean} [options.auth.cookies.httpOnly=true] - Not accessible by JavaScript
 * @param {string} [options.auth.cookies.sameSite='Strict'] - SameSite policy
 * @param {number} [options.auth.cookies.defaultMaxAge=2592000] - Default TTL in seconds (30 days)
 * @param {boolean} [options.auth.cookies.signCookies=true] - Sign cookies with ECDSA
 * @param {object} [options.auth.tokens] - Token manager options
 * @param {number} [options.auth.tokens.defaultTTL=604800] - Default TTL in seconds (7 days)
 * @param {number} [options.maxBodySize=524288] - Maximum request body size in bytes
 * @returns {Server} Configured Obsidiana server instance
 */
function createObsidiana(options = {}) {
  return new Server(options);
}

/**
 * Built-in middleware factories for common tasks.
 *
 * @namespace middleware
 * @property {Function} cors - CORS middleware factory
 * @property {Function} logger - Request logging middleware factory
 * @property {Function} securityHeaders - Security headers middleware factory (XSS, CSP, HSTS)
 * @property {Function} rateLimit - Rate limiting middleware factory
 */
const middleware = { cors, logger, securityHeaders, rateLimit };

/**
 * @exports
 * @property {Function} createObsidiana - Main server factory
 * @property {Function} serveStatic - Static file serving middleware
 * @property {Object} middleware - Built-in middleware collection
 * @property {Function} requireAuth - Middleware to require authentication
 * @property {Function} optionalAuth - Middleware for optional authentication
 */
module.exports = {
  createObsidiana,
  serveStatic,
  middleware,
  requireAuth,
  optionalAuth,
};
