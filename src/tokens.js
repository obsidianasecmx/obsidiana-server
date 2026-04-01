"use strict";

/**
 * Obsidiana Secure Tokens — Encrypted tokens with identity key.
 *
 * Provides stateless, encrypted tokens for authentication across all platforms.
 * Tokens are AES-GCM-256 encrypted and ECDSA-signed using the server's identity
 * keypair. Format: v1:encrypted:signature.
 *
 * Features:
 * - AES-GCM-256 encryption with identity-derived key
 * - ECDSA signature for integrity
 * - Stateless (all data is in the token)
 * - Optional revocation via in-memory blacklist
 * - Automatic expiration (iat + exp)
 *
 * @module tokens
 * @private
 */

const { ObsidianaECDSA } = require("@obsidianasecmx/obsidiana-protocol");

/**
 * Manager for encrypted stateless tokens.
 *
 * @example
 * const tokens = new ObsidianaTokenManager(identity);
 * await tokens.init();
 * const token = await tokens.generate({ userId: 123, role: 'admin' });
 * const payload = await tokens.verify(token);
 */
class ObsidianaTokenManager {
  /**
   * Creates a new token manager instance.
   *
   * @param {ObsidianaIdentity} identity - Identity keypair for signatures
   * @param {object} [options] - Optional configuration
   * @param {number} [options.defaultTTL=604800] - Default TTL in seconds (7 days)
   */
  constructor(identity, options = {}) {
    /** @private {ObsidianaIdentity} Identity keypair */
    this._identity = identity;

    /** @private {number} Default TTL in seconds */
    this._defaultTTL = options.defaultTTL ?? 7 * 24 * 60 * 60;

    /** @private {Set<string>} Revoked token IDs (jti) */
    this._revokedTokens = new Set();

    /** @private {CryptoKey|null} AES key derived from identity key */
    this._encryptionKey = null;
  }

  /**
   * Initializes the manager by deriving the encryption key.
   *
   * @returns {Promise<this>} Current instance for method chaining
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
   * Converts a base64 or base64url string to Uint8Array.
   *
   * @param {string} base64 - Base64 or base64url encoded string
   * @returns {Uint8Array} Decoded bytes
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
   * Converts a Uint8Array to a base64url string.
   *
   * @param {Uint8Array} uint8 - Bytes to encode
   * @returns {string} Base64url-encoded string
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
   * @param {number} bytes - Number of random bytes
   * @returns {string} Hex string of length bytes * 2
   * @private
   */
  _randomHex(bytes) {
    const arr = crypto.getRandomValues(new Uint8Array(bytes));
    return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Generates an encrypted, signed token.
   *
   * @param {object} payload - Data to embed in the token (userId, role, etc.)
   * @param {number} [ttlSeconds] - Time to live in seconds (defaults to defaultTTL)
   * @returns {Promise<string>} Encrypted token (v1:encrypted:signature)
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
   * Verifies, decrypts, and returns a token's payload.
   *
   * @param {string} token - Encrypted token
   * @returns {Promise<object|null>} Decrypted payload or null if invalid/expired/revoked
   */
  async verify(token) {
    const parts = token.split(":");
    if (parts.length !== 3 || parts[0] !== "v1") return null;

    const encryptedPayload = this._base64ToUint8Array(parts[1]);
    const signature = parts[2];

    // Verify signature
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

      // Check expiration
      if (Date.now() > payload.exp) return null;

      // Check revocation
      if (this._revokedTokens.has(payload.jti)) return null;

      return payload;
    } catch {
      return null;
    }
  }

  /**
   * Revokes a token by its JTI (token ID).
   *
   * Revoked tokens are automatically removed after 7 days.
   *
   * @param {string} jti - Token ID to revoke
   */
  revoke(jti) {
    this._revokedTokens.add(jti);
    // Auto-cleanup after TTL
    setTimeout(() => this._revokedTokens.delete(jti), 7 * 24 * 60 * 60 * 1000);
  }
}

/**
 * @exports
 * @property {Class} ObsidianaTokenManager - Encrypted token manager
 */
module.exports = { ObsidianaTokenManager };
