"use strict";

/**
 * Request wrapper – extends Node.js IncomingMessage with helpers.
 *
 * Adds properties:
 * - `req.query` – URLSearchParams
 * - `req.pathname` – parsed pathname
 * - `req.params` – route parameters (populated by router)
 * - `req.body` – parsed body (populated by middleware)
 * - `req.rawBody(limit)` – reads and buffers the raw request body
 *
 * @module request
 * @private
 */

const DEFAULT_MAX_BODY = 512 * 1024; // 512 KB

/**
 * Wraps a raw Node.js request, augmenting it with helper methods.
 *
 * @param {import("http").IncomingMessage} req - Raw request
 * @param {string} baseUrl - Base URL for parsing (e.g., `http://localhost`)
 * @param {object} [options] - Options
 * @param {number} [options.maxBodySize=524288] - Maximum body size in bytes
 * @returns {import("http").IncomingMessage} The same request object with added properties
 */
function wrapRequest(req, baseUrl, options = {}) {
  const parsed = new URL(req.url, baseUrl);
  const maxBodySize = options.maxBodySize ?? DEFAULT_MAX_BODY;

  req.query = parsed.searchParams;
  req.pathname = parsed.pathname;
  req.params = {};
  req.body = null;

  req.rawBody = (limit = maxBodySize) =>
    new Promise((resolve, reject) => {
      const chunks = [];
      let received = 0;

      req.on("data", (chunk) => {
        received += chunk.length;
        if (received > limit) {
          req.destroy();
          const err = new RangeError(`Request body exceeds ${limit} bytes`);
          err.status = 413;
          return reject(err);
        }
        chunks.push(chunk);
      });

      req.on("end", () => {
        const total = chunks.reduce((n, c) => n + c.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const c of chunks) {
          out.set(c, offset);
          offset += c.length;
        }
        resolve(out);
      });

      req.on("error", reject);
    });

  return req;
}

module.exports = { wrapRequest };
