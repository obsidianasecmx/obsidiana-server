"use strict";

/**
 * Obsidiana Response Wrapper — Extends Node.js ServerResponse with helpers.
 *
 * Adds convenience methods to the raw Node.js response object:
 * - `res.send(status, body, headers)` — auto-detects content type
 * - `res.html(status, html, headers)` — sends HTML response
 * - `res.json(status, data, headers)` — sends JSON response (alias for send)
 *
 * All methods are added directly to the original `res` object (mutated in-place).
 * The wrapper also injects Obsidiana-specific response headers.
 *
 * @module response
 * @private
 */

const { STATUS_CODES } = require("http");

/**
 * Default headers added to every response.
 * @private
 */
const OBSIDIAN_HEADERS = {
  "X-Powered-By": "obsidiana-server",
  "X-Obsidiana-Protocol": "obsidiana-v1",
};

/**
 * Wraps Node's ServerResponse with send/html/json helpers.
 *
 * The original `res` object is mutated in-place — no new object is created.
 * This allows middleware to augment the response without breaking compatibility.
 *
 * @param {import("http").ServerResponse} res - Raw Node.js response object
 * @returns {import("http").ServerResponse} The same response object with added methods
 *
 * @example
 * const { wrapResponse } = require('./response');
 *
 * function handleRequest(rawReq, rawRes) {
 *   const res = wrapResponse(rawRes);
 *
 *   // Auto-detect content type
 *   res.send(200, { hello: 'world' }); // → application/json
 *   res.send(200, '<h1>Hello</h1>');   // → text/html (string)
 *   res.send(200, new Uint8Array(...)); // → application/octet-stream
 *
 *   // Explicit HTML
 *   res.html(200, '<h1>Hello</h1>');
 *
 *   // JSON helper
 *   res.json(200, { status: 'ok' });
 * }
 */
function wrapResponse(res) {
  /**
   * Sends a response with automatic content type detection.
   *
   * Content type is determined by `body` type:
   * - `Uint8Array` → `application/octet-stream`
   * - `object` → `application/json; charset=utf-8`
   * - `string` → `text/plain; charset=utf-8`
   *
   * @param {number} status - HTTP status code
   * @param {string | Uint8Array | object} body - Response body
   * @param {Record<string, string>} [headers] - Additional headers to merge
   */
  res.send = (status, body, headers = {}) => {
    if (res.writableEnded) return;

    let payload;
    let contentType;

    if (body instanceof Uint8Array) {
      payload = body;
      contentType = "application/octet-stream";
    } else if (typeof body === "object" && body !== null) {
      payload = JSON.stringify(body);
      contentType = "application/json; charset=utf-8";
    } else {
      payload = String(body ?? STATUS_CODES[status] ?? "");
      contentType = "text/plain; charset=utf-8";
    }

    res.writeHead(status, {
      ...OBSIDIAN_HEADERS,
      "Content-Type": contentType,
      "Content-Length": Buffer.byteLength(payload),
      ...headers,
    });

    res.end(payload);
  };

  /**
   * Sends an HTML response.
   *
   * Sets `Content-Type: text/html; charset=utf-8` automatically.
   *
   * @param {number} status - HTTP status code
   * @param {string} html - HTML string to send
   * @param {Record<string, string>} [headers] - Additional headers to merge
   */
  res.html = (status, html, headers = {}) => {
    if (res.writableEnded) return;
    const payload = String(html);
    res.writeHead(status, {
      ...OBSIDIAN_HEADERS,
      "Content-Type": "text/html; charset=utf-8",
      "Content-Length": Buffer.byteLength(payload),
      ...headers,
    });
    res.end(payload);
  };

  /**
   * Sends a JSON response.
   *
   * Alias for `res.send(status, data, headers)`.
   * On encrypted routes, this method is replaced by the crypto middleware
   * to automatically encrypt the response before sending.
   *
   * @param {number} status - HTTP status code
   * @param {object} data - JSON-serializable data
   * @param {Record<string, string>} [headers] - Additional headers to merge
   */
  res.json = (status, data, headers = {}) => res.send(status, data, headers);

  return res;
}

module.exports = { wrapResponse };
