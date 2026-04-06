"use strict";

/**
 * Obsidiana Server – main entry point.
 *
 * Exports:
 * - `createObsidiana(options)` – factory to create a server instance
 * - `serveStatic(root, options)` – static file middleware
 * - `middleware` – built‑in middleware (cors, logger, securityHeaders, rateLimit)
 * - `requireAuth` / `optionalAuth` – authentication helpers
 *
 * @module obsidiana-server
 * @public
 */

const { Server } = require("./src/server");
const { serveStatic } = require("./src/static");
const { cors, logger, securityHeaders, rateLimit } = require("./src/builtins");
const { requireAuth, optionalAuth } = require("./src/auth");

/**
 * Creates a new Obsidiana server instance.
 *
 * @param {object} [options] - Server configuration
 * @param {object} [options.pow] - Proof‑of‑Work options
 * @param {object} [options.rateLimit] - Rate limiting options
 * @param {object} [options.auth] - Authentication options (cookies, tokens)
 * @param {number} [options.maxBodySize=524288] - Maximum request body size in bytes
 * @returns {Server} Configured server instance
 */
function createObsidiana(options = {}) {
  return new Server(options);
}

/**
 * Built‑in middleware factories.
 *
 * @namespace middleware
 */
const middleware = { cors, logger, securityHeaders, rateLimit };

module.exports = {
  createObsidiana,
  serveStatic,
  middleware,
  requireAuth,
  optionalAuth,
};
