"use strict";

/**
 * Obsidiana Crypto Middleware — Automatic encryption/decryption for HTTP routes.
 *
 * This middleware intercepts HTTP requests and responses, automatically
 * decrypting incoming requests and encrypting outgoing responses using the
 * session established during handshake.
 *
 * The middleware:
 * - Bypasses public routes (no encryption)
 * - Resolves session from AAD static hint
 * - Verifies nonce for replay protection
 * - Decrypts request body using AES-GCM-256
 * - Wraps response methods to encrypt all outgoing data
 *
 * Supports both standard AES-GCM and ratchet encryption for forward secrecy.
 *
 * @module crypto-middleware
 * @private
 */

const { ObsidianaCBOR } = require("@obsidianasecmx/obsidiana-protocol");

/**
 * Creates the crypto middleware for automatic encryption/decryption.
 *
 * @param {ObsidianaSessionStore} store - Session store for lookup and nonce tracking
 * @param {string[]} bypassPaths - Paths that skip crypto (e.g., handshake endpoint)
 * @param {Router} router - Router to check route publicity
 * @returns {Function} Express-style middleware (req, res, next) => Promise<void>
 */
function obsidianaCrypto(store, bypassPaths, router) {
  return async function cryptoMiddleware(req, res, next) {
    const routeExists = router.match(req.method, req.pathname);

    if (!routeExists) return next();

    if (routeExists.public) {
      // Parse plaintext body for public routes
      if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
        const raw = await req.rawBody();
        if (raw.length) {
          try {
            req.body = JSON.parse(new TextDecoder().decode(raw));
          } catch {
            req.body = new TextDecoder().decode(raw);
          }
        } else {
          req.body = null;
        }
      }
      return next();
    }

    // Bypass paths (handshake endpoint, root)
    if (bypassPaths.includes(req.pathname) || req.pathname === "/")
      return next();

    // Only handle relevant HTTP methods
    if (!["POST", "PUT", "PATCH", "DELETE", "GET"].includes(req.method))
      return next();

    // Body size limit check (512 KB)
    const contentLength = parseInt(req.headers["content-length"] ?? "0", 10);
    if (contentLength > 512 * 1024) {
      res.send(413);
      return;
    }

    try {
      // Extract encrypted payload (from body or query param for GET)
      let raw;
      if (req.method === "GET" && req.query?.get("_d")) {
        const b64 = req.query.get("_d");
        raw = Uint8Array.from(
          atob(b64.replace(/-/g, "+").replace(/_/g, "/")),
          (c) => c.charCodeAt(0),
        );
      } else {
        raw = await req.rawBody();
      }

      if (!raw.length) {
        res.send(401);
        return;
      }

      const envelope = ObsidianaCBOR.decode(raw);

      if (!envelope?.d) {
        res.send(400);
        return;
      }

      // Resolve session from envelope
      const { aad, sessionId, cipher, ratchet } = await _resolveFromEnvelope(
        envelope,
        store,
      );

      if (!cipher) {
        res.send(401);
        return;
      }

      // Check if ratchet encryption is being used
      const isRatchet = !!(envelope.ct && envelope.hdr);

      // Decrypt the request body
      let plain;
      try {
        if (isRatchet && ratchet) {
          const ct = Uint8Array.from(atob(envelope.ct), (c) => c.charCodeAt(0));
          const hdr = Uint8Array.from(atob(envelope.hdr), (c) =>
            c.charCodeAt(0),
          );
          plain = await ratchet.decrypt(ct, hdr);
        } else {
          plain = await cipher.decrypt(envelope, { sessionId });
        }
      } catch (e) {
        res.send(401);
        return;
      }

      // Anti-replay: verify nonce hasn't been used before
      if (!store.claimNonce(aad.n)) {
        console.log("[crypto] nonce replay");
        res.send(401);
        return;
      }

      // Attach decrypted body and wrap response for encryption
      req.body = plain;
      req._useRatchet = isRatchet;
      _wrapResponse(res, cipher, sessionId, ratchet, req._useRatchet);
      next();
    } catch (err) {
      console.log("[crypto] outer catch:", err.message);
      if (err.status === 413) {
        res.send(413);
      } else {
        res.send(400);
      }
    }
  };
}

/**
 * Resolves session from an encrypted envelope.
 *
 * Extracts the AAD from the envelope, uses the static hint to look up
 * the session in the store, and returns the session data.
 *
 * @param {object} envelope - Encrypted envelope { d, ct?, hdr? }
 * @param {ObsidianaSessionStore} store - Session store
 * @returns {Promise<{ aad: object, sessionId: string, cipher: object, ratchet: object | null } | { cipher: null }>}
 * @private
 */
async function _resolveFromEnvelope(envelope, store) {
  try {
    // Decode base64 blob and extract AAD
    const blob = Uint8Array.from(atob(envelope.d), (c) => c.charCodeAt(0));
    const aadLen = (blob[12] << 8) | blob[13];
    const aadBytes = blob.slice(14, 14 + aadLen);
    const aad = JSON.parse(new TextDecoder().decode(aadBytes));

    // Look up session by static hint
    const result = await store.resolveSession(aad);
    if (!result) return { cipher: null };

    return {
      aad,
      sessionId: result.sessionId,
      cipher: result.cipher,
      ratchet: result.ratchet,
    };
  } catch (e) {
    console.log("[crypto] _resolveFromEnvelope error:", e.message);
    return { cipher: null };
  }
}

/**
 * Wraps response methods to automatically encrypt outgoing data.
 *
 * Replaces `res.json()`, `res.text()`, `res.html()`, and `res.send()`
 * with encrypted versions. The original `_originalSend` is preserved
 * for raw responses.
 *
 * @param {object} res - HTTP response object
 * @param {ObsidianaAES} cipher - AES cipher for encryption
 * @param {string} sessionId - Current session identifier
 * @param {object|null} ratchet - Ratchet instance for forward secrecy (optional)
 * @param {boolean} useRatchet - Whether to use ratchet encryption
 * @private
 */
function _wrapResponse(
  res,
  cipher,
  sessionId,
  ratchet = null,
  useRatchet = false,
) {
  const _originalSend = res.send.bind(res);
  let _sent = false;

  /**
   * Encrypts data and sends the encrypted response.
   *
   * @param {number} status - HTTP status code
   * @param {any} body - Data to encrypt and send
   * @returns {Promise<void>}
   */
  function encryptAndSend(status, body) {
    if (_sent) return Promise.resolve();
    _sent = true;

    const p = (async () => {
      try {
        let wireData;

        if (useRatchet && ratchet) {
          // Ratchet mode: use forward secrecy ratchet
          const { ciphertext, header } = await ratchet.encrypt(body);
          const aadEnvelope = await cipher.encrypt({}, { sessionId });
          wireData = ObsidianaCBOR.encode({
            d: aadEnvelope.d,
            ct: btoa(String.fromCharCode(...ciphertext)),
            hdr: btoa(String.fromCharCode(...header)),
          });
        } else {
          // Standard mode: use AES-GCM
          const envelope = await cipher.encrypt(body, { sessionId });
          wireData = ObsidianaCBOR.encode(envelope);
        }

        _originalSend(status, wireData, { "content-type": "application/cbor" });
      } catch (e) {
        console.log("[crypto] encryptAndSend error:", e.message);
        if (!res.writableEnded) _originalSend(500, "");
      }
    })();

    res._obsidianSend = p;
    return p;
  }

  // Replace response methods with encrypted versions
  res.json = (status, data) => encryptAndSend(status, data);
  res.text = (status, text) => encryptAndSend(status, text);
  res.html = (status, html) => encryptAndSend(status, html);
  res.send = (status, body) => {
    if (typeof body === "string" || typeof body === "object") {
      return encryptAndSend(status, body);
    }
    return _originalSend(status, body);
  };
}

module.exports = { obsidianaCrypto };
