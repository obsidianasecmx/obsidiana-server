"use strict";

/**
 * Obsidiana Static File Server — Middleware for serving static files.
 *
 * Provides a static file serving middleware with:
 * - MIME type detection based on file extension
 * - SPA (Single Page Application) fallback (serves index.html on unmatched routes)
 * - Path traversal protection
 * - Directory index support (serves index.html inside folders)
 * - Cache-Control headers (1 hour default)
 * - Security headers (X-Content-Type-Options, X-Frame-Options)
 * - Conditional requests (ETag, Last-Modified, 304)
 * - Range requests support (partial content)
 *
 * The middleware checks if a route exists in the router before attempting
 * to serve a static file, ensuring encrypted routes take precedence.
 *
 * @module static
 * @public
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

/**
 * MIME type mapping for common file extensions.
 * @private
 */
const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".htm": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".webp": "image/webp",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".otf": "font/otf",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml",
  ".pdf": "application/pdf",
  ".mp4": "video/mp4",
  ".webm": "video/webm",
  ".mp3": "audio/mpeg",
  ".wav": "audio/wav",
};

/** Default MIME type for unknown extensions. @private */
const DEFAULT_MIME = "application/octet-stream";

/** Default cache TTL (1 hour). @private */
const DEFAULT_CACHE_MAX_AGE = 3600;

/** Paths that should never serve static files (security) */
const FORBIDDEN_PATHS = [
  ".env",
  ".git",
  ".obsidiana",
  "node_modules",
  "package.json",
  "package-lock.json",
  "server.key",
  "server.pub",
];

/**
 * Creates a static file serving middleware.
 *
 * The middleware serves files from the specified root directory.
 * If a file is not found and `spa: true` is set, it falls back to
 * serving `index.html` (for client-side routing in SPAs).
 *
 * The middleware checks registered routes first — if a route exists
 * (encrypted endpoint), it passes through instead of serving static files.
 *
 * @param {string} root - Absolute or relative path to the static directory
 * @param {object} [options] - Configuration options
 * @param {boolean} [options.spa=false] - Serve index.html for unmatched routes (SPA fallback)
 * @param {string} [options.index="index.html"] - Default index file name for directories
 * @param {number} [options.maxAge=3600] - Cache max age in seconds
 * @param {boolean} [options.etag=true] - Enable ETag generation
 * @param {boolean} [options.lastModified=true] - Enable Last-Modified header
 * @returns {Function} Express-style middleware (req, res, next) => void
 *
 * @example
 * const { createObsidiana, serveStatic } = require('@obsidianasecmx/obsidiana-server');
 *
 * const app = createObsidiana();
 *
 * // Serve static files from ./public directory
 * app.use(serveStatic('./public'));
 *
 * // SPA mode (React, Vue) — all unmatched routes serve index.html
 * app.use(serveStatic('./dist', { spa: true }));
 *
 * app.listen(3000);
 */
function serveStatic(root, options = {}) {
  const {
    spa = false,
    index = "index.html",
    maxAge = DEFAULT_CACHE_MAX_AGE,
    etag = true,
    lastModified = true,
  } = options;
  const absRoot = path.resolve(root);

  return function staticMiddleware(req, res, next) {
    // Only handle GET and HEAD requests
    if (req.method !== "GET" && req.method !== "HEAD") return next();

    // Get pathname from request (already parsed by wrapRequest)
    const pathname =
      req.pathname ?? decodeURIComponent(new URL(req.url, "http://x").pathname);

    // Check if the path is forbidden
    const normalizedPathname = pathname.toLowerCase();
    if (
      FORBIDDEN_PATHS.some((forbidden) =>
        normalizedPathname.includes(forbidden),
      )
    ) {
      res.send(403);
      return;
    }

    // Check if route exists in router (encrypted routes take precedence)
    const router = req._serverRouter;
    if (router && router.match(req.method, pathname)) {
      return next(); // Let the router handle it
    }

    // Prevent path traversal attacks
    const safePath = path.normalize(pathname).replace(/^(\.\.(\/|\\|$))+/, "");
    let filePath = path.join(absRoot, safePath);

    // Ensure the resolved path is within the static root
    if (!filePath.startsWith(absRoot)) {
      res.send(403);
      return;
    }

    tryServe(filePath, index, spa, absRoot, res, req, next, {
      maxAge,
      etag,
      lastModified,
    });
  };
}

/**
 * Attempts to serve a file, with directory index and SPA fallback support.
 *
 * @param {string} filePath - Absolute path to the requested file
 * @param {string} index - Index file name (e.g., "index.html")
 * @param {boolean} spa - Whether to fall back to index.html on 404
 * @param {string} absRoot - Absolute static root directory
 * @param {object} res - HTTP response object
 * @param {object} req - HTTP request object
 * @param {Function} next - Next middleware function
 * @param {object} options - Serve options
 * @private
 */
function tryServe(filePath, index, spa, absRoot, res, req, next, options) {
  fs.stat(filePath, (err, stat) => {
    if (err) {
      // File not found — try SPA fallback or pass through
      if (spa) {
        const indexPath = path.join(absRoot, index);
        return sendFile(indexPath, res, req, next, options);
      }
      return next();
    }

    // If path is a directory, try to serve index file inside it
    if (stat.isDirectory()) {
      return tryServe(
        path.join(filePath, index),
        index,
        spa,
        absRoot,
        res,
        req,
        next,
        options,
      );
    }

    sendFile(filePath, res, req, next, options);
  });
}

/**
 * Generates an ETag for a file based on inode, size, and mtime.
 *
 * @param {fs.Stats} stat - File statistics
 * @returns {string} ETag value
 * @private
 */
function generateETag(stat) {
  const hash = crypto.createHash("md5");
  hash.update(`${stat.ino}-${stat.size}-${stat.mtimeMs}`);
  return `"${hash.digest("hex")}"`;
}

/**
 * Checks if the client has a valid cached version.
 *
 * @param {object} req - HTTP request
 * @param {fs.Stats} stat - File statistics
 * @param {string} etag - File ETag
 * @returns {boolean} True if client has the latest version
 * @private
 */
function isNotModified(req, stat, etag) {
  const ifNoneMatch = req.headers["if-none-match"];
  const ifModifiedSince = req.headers["if-modified-since"];

  // Check ETag
  if (ifNoneMatch) {
    if (ifNoneMatch === etag || ifNoneMatch === `W/${etag}`) {
      return true;
    }
  }

  // Check Last-Modified
  if (ifModifiedSince) {
    const ifModifiedSinceDate = new Date(ifModifiedSince);
    if (stat.mtime <= ifModifiedSinceDate) {
      return true;
    }
  }

  return false;
}

/**
 * Streams a file to the response with appropriate headers.
 *
 * @param {string} filePath - Absolute path to the file
 * @param {object} res - HTTP response object
 * @param {object} req - HTTP request object
 * @param {Function} next - Next middleware function
 * @param {object} options - Serve options
 * @private
 */
function sendFile(filePath, res, req, next, options) {
  const { maxAge, etag, lastModified } = options;

  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) return next();

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] ?? DEFAULT_MIME;

    // Generate ETag
    const fileETag = etag ? generateETag(stat) : null;

    // Check client cache
    if (fileETag && isNotModified(req, stat, fileETag)) {
      res.writeHead(304, {
        "X-Powered-By": "obsidiana-server",
        "X-Obsidiana-Protocol": "obsidiana-v1",
        "Cache-Control": `public, max-age=${maxAge}`,
        ...(fileETag && { ETag: fileETag }),
        ...(lastModified && { "Last-Modified": stat.mtime.toUTCString() }),
      });
      res.end();
      return;
    }

    // Security headers for static files
    const headers = {
      "X-Powered-By": "obsidiana-server",
      "X-Obsidiana-Protocol": "obsidiana-v1",
      "Content-Type": contentType,
      "Content-Length": stat.size,
      "Cache-Control": `public, max-age=${maxAge}`,
      // Security headers for static files
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "X-XSS-Protection": "1; mode=block",
      "Referrer-Policy": "strict-origin-when-cross-origin",
    };

    // Add ETag if enabled
    if (fileETag) {
      headers["ETag"] = fileETag;
    }

    // Add Last-Modified if enabled
    if (lastModified) {
      headers["Last-Modified"] = stat.mtime.toUTCString();
    }

    // Add Accept-Ranges for streaming support
    headers["Accept-Ranges"] = "bytes";

    // Check if client requests a specific range
    const rangeHeader = req.headers.range;
    if (rangeHeader) {
      const range = parseRange(rangeHeader, stat.size);
      if (range) {
        headers["Content-Range"] =
          `bytes ${range.start}-${range.end}/${stat.size}`;
        headers["Content-Length"] = range.end - range.start + 1;
        res.writeHead(206, headers);

        const stream = fs.createReadStream(filePath, {
          start: range.start,
          end: range.end,
        });
        stream.pipe(res);
        stream.on("error", () => {
          if (!res.writableEnded) res.end();
        });
        return;
      }
    }

    // HEAD requests only need headers
    if (req.method === "HEAD") {
      res.writeHead(200, headers);
      res.end();
      return;
    }

    // Stream the file to response
    res.writeHead(200, headers);
    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
    stream.on("error", () => {
      if (!res.writableEnded) res.end();
    });
  });
}

/**
 * Parses Range header for partial content requests.
 *
 * @param {string} rangeHeader - Range header value (e.g., "bytes=0-1023")
 * @param {number} fileSize - Total file size in bytes
 * @returns {{ start: number, end: number } | null} Parsed range or null if invalid
 * @private
 */
function parseRange(rangeHeader, fileSize) {
  const match = rangeHeader.match(/bytes=(\d+)-(\d*)/);
  if (!match) return null;

  let start = parseInt(match[1], 10);
  let end = match[2] ? parseInt(match[2], 10) : fileSize - 1;

  if (isNaN(start)) start = 0;
  if (isNaN(end)) end = fileSize - 1;

  if (start >= fileSize || end >= fileSize || start > end) return null;

  return { start, end };
}

module.exports = { serveStatic };
