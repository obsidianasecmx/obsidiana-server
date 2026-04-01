"use strict";

/**
 * Obsidiana Built-in Middleware — Common middleware utilities.
 *
 * Provides ready-to-use middleware functions for common tasks:
 * - CORS: Cross-Origin Resource Sharing headers
 * - Logger: Request logging with timing
 * - securityHeaders: Security headers (XSS, CSP, HSTS, etc.)
 * - rateLimit: Rate limiting per IP + endpoint
 *
 * These middleware can be used with `app.use()` or `app.pipeline.use()`.
 *
 * @module builtins
 * @public
 */

/**
 * Creates CORS middleware that adds appropriate headers to responses.
 *
 * The middleware automatically handles OPTIONS preflight requests by
 * responding with 204 No Content and skipping further processing.
 *
 * @param {object} [options] - CORS configuration
 * @param {string} [options.origin="*"] - Allowed origin (e.g., "https://example.com")
 * @param {string} [options.methods="GET,POST,PUT,PATCH,DELETE,OPTIONS"] - Allowed HTTP methods
 * @param {string} [options.headers="Content-Type,Authorization"] - Allowed request headers
 * @returns {Function} Express-style middleware (req, res, next) => void
 *
 * @example
 * const app = createObsidiana();
 * app.use(cors({ origin: "https://myapp.com" }));
 *
 * // Or with default values (allow all)
 * app.use(cors());
 */
function cors(options = {}) {
  const origin = options.origin ?? "*";
  const methods = options.methods ?? "GET,POST,PUT,PATCH,DELETE,OPTIONS";
  const headers = options.headers ?? "Content-Type,Authorization";

  return function corsMiddleware(req, res, next) {
    // Set CORS headers on all responses
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", methods);
    res.setHeader("Access-Control-Allow-Headers", headers);

    // Handle preflight requests
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
 *
 * The log is emitted when the response finishes, capturing the final
 * status code and total processing time.
 *
 * @returns {Function} Express-style middleware (req, res, next) => void
 *
 * @example
 * const app = createObsidiana();
 * app.use(logger());
 *
 * // Output: GET /api/users 200 12ms
 * //         POST /api/data 201 45ms
 */
function logger() {
  return function loggerMiddleware(req, res, next) {
    const start = Date.now();

    // Log when response finishes
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
 * Adds headers to protect against:
 * - XSS (X-XSS-Protection, Content-Security-Policy)
 * - Clickjacking (X-Frame-Options)
 * - MIME sniffing (X-Content-Type-Options)
 * - HSTS (Strict-Transport-Security)
 *
 * @param {object} [options] - Configuration options
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
    // Prevent XSS in older browsers
    res.setHeader("X-XSS-Protection", "1; mode=block");

    // Prevent MIME type sniffing
    res.setHeader("X-Content-Type-Options", "nosniff");

    // Prevent clickjacking
    res.setHeader("X-Frame-Options", "DENY");

    // Referrer policy
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

    // HSTS - force HTTPS
    if (hsts) {
      res.setHeader(
        "Strict-Transport-Security",
        `max-age=${hstsMaxAge}; includeSubDomains; preload`,
      );
    }

    // Content Security Policy
    if (csp) {
      res.setHeader(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
      );
    }

    // Permissions Policy
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
 * Limits the number of requests per IP + endpoint combination.
 * Uses in-memory store with sliding window.
 *
 * @param {object} [options] - Configuration options
 * @param {number} [options.windowMs=60000] - Time window in milliseconds
 * @param {number} [options.max=100] - Maximum requests per window
 * @param {string} [options.message="Too many requests"] - Error message
 * @returns {Function} Express-style middleware (req, res, next) => void
 */
function rateLimit(options = {}) {
  const windowMs = options.windowMs ?? 60000;
  const max = options.max ?? 100;
  const message = options.message ?? "Too many requests";

  const store = new Map();

  // Cleanup expired entries every minute
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
      // New window
      record = {
        count: 1,
        resetTime: now + windowMs,
      };
      store.set(key, record);

      return next();
    }

    // Increment counter
    record.count++;

    if (record.count > max) {
      return res.send(429);
    }

    next();
  };
}

module.exports = { cors, logger, securityHeaders, rateLimit };
