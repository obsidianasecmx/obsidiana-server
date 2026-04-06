"use strict";

/**
 * Response wrapper – extends Node.js ServerResponse with helpers.
 *
 * Adds methods:
 * - `res.send(status, body, headers)` – auto‑detects content type
 * - `res.html(status, html, headers)` – sends HTML
 * - `res.json(status, data, headers)` – sends JSON (alias for send)
 *
 * Injects Obsidiana‑specific headers (`X-Powered-By`, `X-Obsidiana-Protocol`).
 *
 * @module response
 * @private
 */

const { STATUS_CODES } = require("http");

/** @private */
const OBSIDIAN_HEADERS = {
  "X-Powered-By": "obsidiana-server",
  "X-Obsidiana-Protocol": "obsidiana-v1",
};

/**
 * Wraps a raw Node.js response, augmenting it with helper methods.
 *
 * @param {import("http").ServerResponse} res - Raw response
 * @returns {import("http").ServerResponse} The same response object with added methods
 */
function wrapResponse(res) {
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

  res.json = (status, data, headers = {}) => res.send(status, data, headers);

  return res;
}

module.exports = { wrapResponse };
