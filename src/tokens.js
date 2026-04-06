"use strict";

/**
 * Stateless encrypted token manager using the server's identity key.
 *
 * Tokens are AES‑GCM‑256 encrypted and ECDSA‑signed.
 * Format: `v1:encryptedPayload:signature` (base64url).
 *
 * Tokens contain a JTI (random ID) and expiration (iat + exp).
 * Optional revocation is supported via an in‑memory blacklist.
 *
 * @module tokens
 * @private
 */

const { ObsidianaECDSA } = require("@obsidianasecmx/obsidiana-protocol");

/**
 * Token manager.
 */
class ObsidianaTokenManager {
  /**
   * @param {ObsidianaIdentity} identity - Server identity keypair
   * @param {object} [options]
   * @param {number} [options.defaultTTL=604800] - Default TTL in seconds (7 days)
   */
  constructor(identity, options = {}) {
    /** @private {ObsidianaIdentity} */
    this._identity = identity;

    /** @private {number} */
    this._defaultTTL = options.defaultTTL ?? 7 * 24 * 60 * 60;

    /** @private {Set<string>} */
    this._revokedTokens = new Set();

    /** @private {CryptoKey|null} */
    this._encryptionKey = null;
  }

  /**
   * Initialises the manager (derives AES key).
   *
   * @returns {Promise<this>}
   */
  async init() {
    if (!this._encryptionKey) {
      const fs = require("fs");
      const path = require("path");
      const privJwk = JSON.parse(
        fs.readFileSync(
          path.join(process.cwd(), ".obsidiana", "server.key"),
          "utf8",
        ),
      );

      const privRaw = this._base64ToUint8Array(privJwk.d);
      const salt = new TextEncoder().encode("obsidiana-token-v2");
      const info = new TextEncoder().encode("aes-256-gcm-key");

      const hkdfKey = await crypto.subtle.importKey(
        "raw",
        privRaw,
        { name: "HKDF" },
        false,
        ["deriveBits"],
      );

      const keyBits = await crypto.subtle.deriveBits(
        { name: "HKDF", salt, info, hash: "SHA-256" },
        hkdfKey,
        256,
      );

      this._encryptionKey = await crypto.subtle.importKey(
        "raw",
        keyBits,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"],
      );
    }
    return this;
  }

  /**
   * Converts base64url to Uint8Array.
   *
   * @param {string} base64
   * @returns {Uint8Array}
   * @private
   */
  _base64ToUint8Array(base64) {
    let b64 = base64.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) {
      b64 += "=";
    }
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Converts Uint8Array to base64url.
   *
   * @param {Uint8Array} uint8
   * @returns {string}
   * @private
   */
  _uint8ArrayToBase64(uint8) {
    let binary = "";
    for (let i = 0; i < uint8.length; i++) {
      binary += String.fromCharCode(uint8[i]);
    }
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  /**
   * Generates a random hex string.
   *
   * @param {number} bytes
   * @returns {string}
   * @private
   */
  _randomHex(bytes) {
    const arr = crypto.getRandomValues(new Uint8Array(bytes));
    return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Generates a new encrypted token.
   *
   * @param {object} payload - Data to embed (e.g., userId)
   * @param {number} [ttlSeconds] - TTL in seconds (defaults to defaultTTL)
   * @returns {Promise<string>} Encrypted token
   */
  async generate(payload, ttlSeconds = this._defaultTTL) {
    const tokenPayload = {
      ...payload,
      iat: Date.now(),
      exp: Date.now() + ttlSeconds * 1000,
      jti: this._randomHex(16),
    };

    const plaintext = JSON.stringify(tokenPayload);
    const plainBytes = new TextEncoder().encode(plaintext);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      this._encryptionKey,
      plainBytes,
    );

    const encryptedBytes = new Uint8Array(encrypted);
    const payloadBytes = new Uint8Array(12 + encryptedBytes.length);
    payloadBytes.set(iv, 0);
    payloadBytes.set(encryptedBytes, 12);

    const signature = await this._identity.sign(payloadBytes);

    return `v1:${this._uint8ArrayToBase64(payloadBytes)}:${signature}`;
  }

  /**
   * Verifies, decrypts and returns a token’s payload.
   *
   * @param {string} token - Encrypted token
   * @returns {Promise<object|null>} Decrypted payload or null
   */
  async verify(token) {
    const parts = token.split(":");
    if (parts.length !== 3 || parts[0] !== "v1") return null;

    const encryptedPayload = this._base64ToUint8Array(parts[1]);
    const signature = parts[2];

    const isValid = await ObsidianaECDSA.verify(
      this._identity.publicKey,
      encryptedPayload,
      signature,
    );
    if (!isValid) return null;

    if (encryptedPayload.length < 28) return null;

    const iv = encryptedPayload.slice(0, 12);
    const ciphertext = encryptedPayload.slice(12);

    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        this._encryptionKey,
        ciphertext,
      );
      const decryptedBytes = new Uint8Array(decrypted);
      const decoded = new TextDecoder().decode(decryptedBytes);
      const payload = JSON.parse(decoded);

      if (Date.now() > payload.exp) return null;
      if (this._revokedTokens.has(payload.jti)) return null;

      return payload;
    } catch {
      return null;
    }
  }

  /**
   * Revokes a token by its JTI.
   *
   * @param {string} jti - Token ID
   */
  revoke(jti) {
    this._revokedTokens.add(jti);
    setTimeout(() => this._revokedTokens.delete(jti), 7 * 24 * 60 * 60 * 1000);
  }
}

module.exports = { ObsidianaTokenManager };
