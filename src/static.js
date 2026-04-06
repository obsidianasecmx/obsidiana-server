"use strict";

/**
 * Static file server middleware.
 *
 * Serves files from a given root directory with:
 * - MIME type detection
 * - SPA fallback (serves index.html on 404)
 * - Path traversal protection
 * - ETag and Last‑Modified support (304 responses)
 * - Range requests (partial content)
 * - Cache‑Control headers (1 hour default)
 *
 * The middleware checks the router first: if a route matches, it is skipped.
 *
 * @module static
 * @public
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

/** @private */
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

const DEFAULT_MIME = "application/octet-stream";
const DEFAULT_CACHE_MAX_AGE = 3600;
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
 * Creates static file serving middleware.
 *
 * @param {string} root - Static files root directory
 * @param {object} [options] - Options
 * @param {boolean} [options.spa=false] - Serve index.html on 404 (SPA mode)
 * @param {string} [options.index="index.html"] - Index file name
 * @param {number} [options.maxAge=3600] - Cache max age in seconds
 * @param {boolean} [options.etag=true] - Enable ETag generation
 * @param {boolean} [options.lastModified=true] - Enable Last‑Modified header
 * @returns {Function} Express‑style middleware
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
    if (req.method !== "GET" && req.method !== "HEAD") return next();

    const pathname =
      req.pathname ?? decodeURIComponent(new URL(req.url, "http://x").pathname);

    const normalizedPathname = pathname.toLowerCase();
    if (
      FORBIDDEN_PATHS.some((forbidden) =>
        normalizedPathname.includes(forbidden),
      )
    ) {
      res.send(403);
      return;
    }

    const router = req._serverRouter;
    if (router && router.match(req.method, pathname)) {
      return next();
    }

    const safePath = path.normalize(pathname).replace(/^(\.\.(\/|\\|$))+/, "");
    let filePath = path.join(absRoot, safePath);

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
 * Attempts to serve a file, handling directories and SPA fallback.
 *
 * @private
 */
function tryServe(filePath, index, spa, absRoot, res, req, next, options) {
  fs.stat(filePath, (err, stat) => {
    if (err) {
      if (spa) {
        const indexPath = path.join(absRoot, index);
        return sendFile(indexPath, res, req, next, options);
      }
      return next();
    }

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
 * Generates an ETag for a file.
 *
 * @param {fs.Stats} stat
 * @returns {string}
 * @private
 */
function generateETag(stat) {
  const hash = crypto.createHash("md5");
  hash.update(`${stat.ino}-${stat.size}-${stat.mtimeMs}`);
  return `"${hash.digest("hex")}"`;
}

/**
 * Checks if the client has a cached version (304).
 *
 * @param {object} req
 * @param {fs.Stats} stat
 * @param {string} etag
 * @returns {boolean}
 * @private
 */
function isNotModified(req, stat, etag) {
  const ifNoneMatch = req.headers["if-none-match"];
  const ifModifiedSince = req.headers["if-modified-since"];

  if (ifNoneMatch) {
    if (ifNoneMatch === etag || ifNoneMatch === `W/${etag}`) {
      return true;
    }
  }

  if (ifModifiedSince) {
    const ifModifiedSinceDate = new Date(ifModifiedSince);
    if (stat.mtime <= ifModifiedSinceDate) {
      return true;
    }
  }

  return false;
}

/**
 * Streams a file to the response.
 *
 * @private
 */
function sendFile(filePath, res, req, next, options) {
  const { maxAge, etag, lastModified } = options;

  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) return next();

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] ?? DEFAULT_MIME;

    const fileETag = etag ? generateETag(stat) : null;

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

    const headers = {
      "X-Powered-By": "obsidiana-server",
      "X-Obsidiana-Protocol": "obsidiana-v1",
      "Content-Type": contentType,
      "Content-Length": stat.size,
      "Cache-Control": `public, max-age=${maxAge}`,
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "X-XSS-Protection": "1; mode=block",
      "Referrer-Policy": "strict-origin-when-cross-origin",
    };

    if (fileETag) headers["ETag"] = fileETag;
    if (lastModified) headers["Last-Modified"] = stat.mtime.toUTCString();
    headers["Accept-Ranges"] = "bytes";

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

    if (req.method === "HEAD") {
      res.writeHead(200, headers);
      res.end();
      return;
    }

    res.writeHead(200, headers);
    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
    stream.on("error", () => {
      if (!res.writableEnded) res.end();
    });
  });
}

/**
 * Parses a Range header.
 *
 * @param {string} rangeHeader - e.g. "bytes=0-1023"
 * @param {number} fileSize
 * @returns {object|null} { start, end } or null
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
