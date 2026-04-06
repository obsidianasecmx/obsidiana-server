"use strict";

/**
 * Obsidiana Server — HTTP/WebSocket framework with end-to-end encryption.
 *
 * Provides transparent E2E encryption for HTTP and WebSocket routes,
 * automatic handshake management, dynamic Proof-of-Work, session storage,
 * and middleware support.
 *
 * @module obsidiana-server
 */

const { Server } = require("./src/server");
const { serveStatic } = require("./src/static");
const { cors, logger, securityHeaders, rateLimit } = require("./src/builtins");
const { requireAuth, optionalAuth } = require("./src/auth");

/**
 * Creates and returns a new Obsidiana server instance.
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
 * @property {Function} securityHeaders - Security headers middleware factory
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
