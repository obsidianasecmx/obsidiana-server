"use strict";

/**
 * Built‑in middleware for common server tasks.
 *
 * Provides ready‑to‑use middleware factories:
 * - CORS: Cross‑Origin Resource Sharing headers
 * - Logger: Request logging with timing
 * - securityHeaders: Security headers (XSS, CSP, HSTS, etc.)
 * - rateLimit: In‑memory rate limiting per IP + endpoint
 *
 * @module builtins
 * @public
 */

/**
 * Creates CORS middleware.
 *
 * Adds `Access-Control-Allow-Origin`, `Allow-Methods` and `Allow-Headers`
 * headers. Handles OPTIONS preflight requests by returning 204.
 *
 * @param {object} [options] - CORS configuration
 * @param {string} [options.origin="*"] - Allowed origin
 * @param {string} [options.methods="GET,POST,PUT,PATCH,DELETE,OPTIONS"] - Allowed HTTP methods
 * @param {string} [options.headers="Content-Type,Authorization"] - Allowed request headers
 * @returns {Function} Express-style middleware (req, res, next) => void
 */
function cors(options = {}) {
  const origin = options.origin ?? "*";
  const methods = options.methods ?? "GET,POST,PUT,PATCH,DELETE,OPTIONS";
  const headers = options.headers ?? "Content-Type,Authorization";

  return function corsMiddleware(req, res, next) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", methods);
    res.setHeader("Access-Control-Allow-Headers", headers);

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    next();
  };
}

/**
 * Creates request logging middleware.
 *
 * Logs each request to stdout in the format:
 * `METHOD pathname statusCode durationMs`
 * The log is emitted when the response finishes.
 *
 * @returns {Function} Express-style middleware (req, res, next) => void
 */
function logger() {
  return function loggerMiddleware(req, res, next) {
    const start = Date.now();

    res.on("finish", () => {
      const ms = Date.now() - start;
      console.log(
        `${req.method} ${req.pathname ?? req.url} ${res.statusCode} ${ms}ms`,
      );
    });

    next();
  };
}

/**
 * Creates security headers middleware.
 *
 * Adds headers to protect against XSS, clickjacking, MIME sniffing,
 * and enables HSTS + a strict CSP by default.
 *
 * @param {object} [options] - Configuration
 * @param {boolean} [options.hsts=true] - Enable HSTS header
 * @param {number} [options.hstsMaxAge=31536000] - HSTS max age in seconds
 * @param {boolean} [options.csp=true] - Enable CSP header
 * @returns {Function} Express-style middleware (req, res, next) => void
 */
function securityHeaders(options = {}) {
  const hsts = options.hsts !== false;
  const hstsMaxAge = options.hstsMaxAge ?? 31536000;
  const csp = options.csp !== false;

  return function securityHeadersMiddleware(req, res, next) {
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

    if (hsts) {
      res.setHeader(
        "Strict-Transport-Security",
        `max-age=${hstsMaxAge}; includeSubDomains; preload`,
      );
    }

    if (csp) {
      res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
      );
    }

    res.setHeader(
      "Permissions-Policy",
      "geolocation=(), microphone=(), camera=(), payment=()",
    );

    next();
  };
}

/**
 * Creates rate limiting middleware.
 *
 * Uses an in‑memory store with a sliding window per IP + method + path.
 * Expired entries are cleaned every minute.
 *
 * @param {object} [options] - Configuration
 * @param {number} [options.windowMs=60000] - Time window in milliseconds
 * @param {number} [options.max=100] - Maximum requests per window
 * @param {string} [options.message="Too many requests"] - Error message (status 429)
 * @returns {Function} Express-style middleware (req, res, next) => void
 */
function rateLimit(options = {}) {
  const windowMs = options.windowMs ?? 60000;
  const max = options.max ?? 100;
  const message = options.message ?? "Too many requests";

  const store = new Map();

  setInterval(() => {
    const now = Date.now();
    for (const [key, record] of store) {
      if (now > record.resetTime) {
        store.delete(key);
      }
    }
  }, 60000);

  return function rateLimitMiddleware(req, res, next) {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const key = `${ip}:${req.method}:${req.pathname}`;
    const now = Date.now();

    let record = store.get(key);

    if (!record || now > record.resetTime) {
      record = { count: 1, resetTime: now + windowMs };
      store.set(key, record);
      return next();
    }

    record.count++;

    if (record.count > max) {
      return res.send(429);
    }

    next();
  };
}

module.exports = { cors, logger, securityHeaders, rateLimit };
