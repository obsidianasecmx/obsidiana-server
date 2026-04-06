"use strict";

/**
 * Crypto middleware for automatic HTTP request/response encryption.
 *
 * Intercepts requests and responses, decrypts incoming bodies using the
 * session established during handshake, and encrypts outgoing responses.
 *
 * Supports both standard AES‑GCM and ratchet encryption (forward secrecy).
 * Bypasses public routes and the handshake endpoint.
 *
 * @module crypto-middleware
 * @private
 */

const { ObsidianaCBOR } = require("@obsidianasecmx/obsidiana-protocol");

/**
 * Factory for the crypto middleware.
 *
 * @param {ObsidianaSessionStore} store - Session store for lookups and nonce tracking
 * @param {string[]} bypassPaths - Paths that skip encryption (e.g., handshake endpoint)
 * @param {Router} router - Router to check route publicity
 * @returns {Function} Express-style middleware (req, res, next) => Promise<void>
 */
function obsidianaCrypto(store, bypassPaths, router) {
  return async function cryptoMiddleware(req, res, next) {
    const routeExists = router.match(req.method, req.pathname);

    if (!routeExists) return next();

    if (routeExists.public) {
      // For public routes, parse plaintext body
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

    // Bypass handshake endpoint and root
    if (bypassPaths.includes(req.pathname) || req.pathname === "/")
      return next();

    if (!["POST", "PUT", "PATCH", "DELETE", "GET"].includes(req.method))
      return next();

    // Enforce 512 KB body limit
    const contentLength = parseInt(req.headers["content-length"] ?? "0", 10);
    if (contentLength > 512 * 1024) {
      res.send(413);
      return;
    }

    try {
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

      const { aad, sessionId, cipher, ratchet } = await _resolveFromEnvelope(
        envelope,
        store,
      );

      if (!cipher) {
        res.send(401);
        return;
      }

      const isRatchet = !!(envelope.ct && envelope.hdr);

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
      } catch {
        res.send(401);
        return;
      }

      // Replay protection: nonce must be unused
      if (!store.claimNonce(aad.n)) {
        console.log("[crypto] nonce replay");
        res.send(401);
        return;
      }

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
 * Resolves a session from an encrypted envelope.
 *
 * Extracts the AAD (additional authenticated data) from the envelope,
 * uses the static hint to look up the session, and returns the cipher
 * and optional ratchet.
 *
 * @param {object} envelope - Encrypted envelope { d, ct?, hdr? }
 * @param {ObsidianaSessionStore} store - Session store
 * @returns {Promise<{ aad: object, sessionId: string, cipher: object, ratchet: object | null } | { cipher: null }>}
 * @private
 */
async function _resolveFromEnvelope(envelope, store) {
  try {
    const blob = Uint8Array.from(atob(envelope.d), (c) => c.charCodeAt(0));
    const aadLen = (blob[12] << 8) | blob[13];
    const aadBytes = blob.slice(14, 14 + aadLen);
    const aad = JSON.parse(new TextDecoder().decode(aadBytes));

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
 * Replaces `res.json()`, `res.text()`, `res.html()` and `res.send()`
 * with encrypted versions. The original `res.send` is preserved as
 * `_originalSend` for raw responses.
 *
 * @param {object} res - HTTP response object
 * @param {ObsidianaAES} cipher - AES cipher for encryption
 * @param {string} sessionId - Current session identifier
 * @param {object|null} ratchet - Ratchet instance (optional)
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
          const { ciphertext, header } = await ratchet.encrypt(body);
          const aadEnvelope = await cipher.encrypt({}, { sessionId });
          wireData = ObsidianaCBOR.encode({
            d: aadEnvelope.d,
            ct: btoa(String.fromCharCode(...ciphertext)),
            hdr: btoa(String.fromCharCode(...header)),
          });
        } else {
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
