"use strict";

/**
 * Obsidiana Request Wrapper — Extends Node.js IncomingMessage with helpers.
 *
 * Adds convenience properties and methods to the raw Node.js request object:
 * - `req.query` — URLSearchParams from the request URL
 * - `req.pathname` — parsed pathname (without query string)
 * - `req.params` — route parameters (populated by the router)
 * - `req.body` — parsed body (populated by body middleware)
 * - `req.rawBody(limit)` — Promise that reads and buffers the raw request body
 *
 * @module request
 * @private
 */

const DEFAULT_MAX_BODY = 512 * 1024;

/**
 * Wraps Node's IncomingMessage with parsed helpers and body reading utilities.
 *
 * @param {import("http").IncomingMessage} req - Raw Node.js request object
 * @param {string} baseUrl - Base URL for parsing
 * @param {object} [options] - Configuration options
 * @param {number} [options.maxBodySize=524288] - Maximum body size in bytes
 * @returns {import("http").IncomingMessage} The same request object with added properties
 */
function wrapRequest(req, baseUrl, options = {}) {
  const parsed = new URL(req.url, baseUrl);
  const maxBodySize = options.maxBodySize ?? DEFAULT_MAX_BODY;

  /** @type {URLSearchParams} */
  req.query = parsed.searchParams;

  /** @type {string} */
  req.pathname = parsed.pathname;

  /**
   * Route parameters populated by the router.
   * @type {Record<string, string>}
   */
  req.params = {};

  /**
   * Parsed request body (populated by body middleware).
   * @type {any}
   */
  req.body = null;

  /**
   * Reads and buffers the raw request body as a Uint8Array.
   *
   * @param {number} [limit] - Override the default limit for this call
   * @returns {Promise<Uint8Array>} Raw request body bytes
   * @throws {RangeError} If body exceeds the size limit (status 413)
   */
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
