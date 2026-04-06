"use strict";

/**
 * Obsidiana Response Wrapper — Extends Node.js ServerResponse with helpers.
 *
 * Adds convenience methods to the raw Node.js response object:
 * - `res.send(status, body, headers)` — auto-detects content type
 * - `res.html(status, html, headers)` — sends HTML response
 * - `res.json(status, data, headers)` — sends JSON response (alias for send)
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
 * @param {import("http").ServerResponse} res - Raw Node.js response object
 * @returns {import("http").ServerResponse} The same response object with added methods
 */
function wrapResponse(res) {
  /**
   * Sends a response with automatic content type detection.
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
   * @param {number} status - HTTP status code
   * @param {object} data - JSON-serializable data
   * @param {Record<string, string>} [headers] - Additional headers to merge
   */
  res.json = (status, data, headers = {}) => res.send(status, data, headers);

  return res;
}

module.exports = { wrapResponse };
