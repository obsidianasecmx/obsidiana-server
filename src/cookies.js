"use strict";

/**
 * Encrypted cookie manager using the server's identity key.
 *
 * Provides AES‑GCM‑256 encryption and optional ECDSA signatures for cookies.
 * The encryption key is derived from the server’s persistent identity key
 * via HKDF, ensuring that cookies survive server restarts.
 *
 * Cookie format: `v1:encryptedPayload[:signature]` (base64url).
 *
 * @module cookies
 * @private
 */

const { ObsidianaECDSA } = require("@obsidianasecmx/obsidiana-protocol");

/** Prefix for all secure cookies to avoid collisions. @private */
const COOKIE_PREFIX = "__Secure-obs-";

/**
 * Manager for identity‑key encrypted cookies.
 *
 * @example
 * const cookies = new ObsidianaCookieManager(identity);
 * await cookies.init();
 * await cookies.set(res, 'theme', 'dark');
 * const theme = await cookies.get(req, 'theme');
 */
class ObsidianaCookieManager {
  /**
   * Creates a new cookie manager.
   *
   * @param {ObsidianaIdentity} identity - Persistent server identity keypair
   * @param {object} [options] - Optional settings
   * @param {boolean} [options.secure=true] - HTTPS only flag
   * @param {boolean} [options.httpOnly=true] - Not accessible via JavaScript
   * @param {string} [options.sameSite='Strict'] - SameSite policy
   * @param {number} [options.defaultMaxAge=2592000] - Default TTL in seconds (30 days)
   * @param {boolean} [options.signCookies=true] - Sign cookies with ECDSA
   */
  constructor(identity, options = {}) {
    /** @private {ObsidianaIdentity} */
    this._identity = identity;

    /** @private {boolean} */
    this._secure = options.secure ?? true;

    /** @private {boolean} */
    this._httpOnly = options.httpOnly ?? true;

    /** @private {string} */
    this._sameSite = options.sameSite ?? "Strict";

    /** @private {number} */
    this._defaultMaxAge = options.defaultMaxAge ?? 30 * 24 * 60 * 60;

    /** @private {boolean} */
    this._signCookies = options.signCookies ?? true;

    /** @private {CryptoKey|null} */
    this._encryptionKey = null;
  }

  /**
   * Initialises the manager by deriving the AES‑GCM key.
   *
   * @returns {Promise<this>} This instance for chaining
   */
  async init() {
    if (!this._encryptionKey) {
      this._encryptionKey = await this._deriveKey();
    }
    return this;
  }

  /**
   * Derives an AES‑256‑GCM key from the server’s identity private key.
   *
   * Reads the private JWK from `.obsidiana/server.key` and uses HKDF
   * with a fixed salt to obtain a deterministic key.
   *
   * @returns {Promise<CryptoKey>} AES‑GCM key
   * @private
   */
  async _deriveKey() {
    const fs = require("fs");
    const path = require("path");
    const privJwk = JSON.parse(
      fs.readFileSync(
        path.join(process.cwd(), ".obsidiana", "server.key"),
        "utf8",
      ),
    );

    const privRaw = this._base64ToUint8Array(privJwk.d);
    const salt = new TextEncoder().encode("obsidiana-cookie-v2");
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

    return await crypto.subtle.importKey(
      "raw",
      keyBits,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
  }

  /**
   * Converts a base64 or base64url string to Uint8Array.
   *
   * @param {string} base64 - Encoded string
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
   * @returns {string} Base64url string
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
   * Encrypts a value for cookie storage.
   *
   * @param {any} value - Value to encrypt (will be JSON stringified)
   * @returns {Promise<string>} Encrypted cookie value
   * @private
   */
  async _encryptValue(value) {
    const plaintext = JSON.stringify(value);
    const plainBytes = new TextEncoder().encode(plaintext);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      this._encryptionKey,
      plainBytes,
    );

    const encryptedBytes = new Uint8Array(encrypted);
    const payload = new Uint8Array(12 + encryptedBytes.length);
    payload.set(iv, 0);
    payload.set(encryptedBytes, 12);

    let cookieValue = `v1:${this._uint8ArrayToBase64(payload)}`;

    if (this._signCookies) {
      const signature = await this._identity.sign(payload);
      cookieValue += `:${signature}`;
    }

    return cookieValue;
  }

  /**
   * Decrypts a cookie value.
   *
   * @param {string} cookieValue - Encrypted cookie string
   * @returns {Promise<any>} Decrypted value or null if invalid
   * @private
   */
  async _decryptValue(cookieValue) {
    const parts = cookieValue.split(":");
    if (parts.length < 2) return null;
    if (parts[0] !== "v1") return null;

    const encryptedData = parts[1];
    const signature = parts[2];
    const payload = this._base64ToUint8Array(encryptedData);

    if (signature && this._signCookies) {
      const isValid = await ObsidianaECDSA.verify(
        this._identity.publicKey,
        payload,
        signature,
      );
      if (!isValid) return null;
    }

    if (payload.length < 28) return null;

    const iv = payload.slice(0, 12);
    const ciphertext = payload.slice(12);

    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        this._encryptionKey,
        ciphertext,
      );
      const decryptedBytes = new Uint8Array(decrypted);
      const decoded = new TextDecoder().decode(decryptedBytes);
      return JSON.parse(decoded);
    } catch {
      return null;
    }
  }

  /**
   * Sets an encrypted cookie.
   *
   * @param {object} res - HTTP response object
   * @param {string} name - Cookie name (will be prefixed)
   * @param {any} value - Value to encrypt and store
   * @param {object} [options] - Cookie options (maxAge, path, etc.)
   * @returns {Promise<void>}
   */
  async set(res, name, value, options = {}) {
    const encrypted = await this._encryptValue(value);
    const maxAge = options.maxAge ?? this._defaultMaxAge;

    const cookieOptions = {
      httpOnly: this._httpOnly,
      secure: this._secure,
      sameSite: this._sameSite,
      path: options.path ?? "/",
      ...options,
    };
    if (maxAge > 0) cookieOptions.maxAge = maxAge;

    res.setHeader(
      "Set-Cookie",
      this._serialize(`${COOKIE_PREFIX}${name}`, encrypted, cookieOptions),
    );
  }

  /**
   * Gets and decrypts a cookie.
   *
   * @param {object} req - HTTP request object
   * @param {string} name - Cookie name (without prefix)
   * @returns {Promise<any>} Decrypted value or null
   */
  async get(req, name) {
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) return null;

    const cookies = this._parse(cookieHeader);
    const raw = cookies[`${COOKIE_PREFIX}${name}`];
    if (!raw) return null;

    return this._decryptValue(raw);
  }

  /**
   * Removes a cookie by setting its Max‑Age to 0.
   *
   * @param {object} res - HTTP response object
   * @param {string} name - Cookie name
   */
  remove(res, name) {
    res.setHeader(
      "Set-Cookie",
      `${COOKIE_PREFIX}${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict`,
    );
  }

  /**
   * Parses the Cookie header into an object.
   *
   * @param {string} header - Raw Cookie header value
   * @returns {object} Map of cookie names to values
   * @private
   */
  _parse(header) {
    const cookies = {};
    header.split(";").forEach((c) => {
      const [k, v] = c.trim().split("=");
      if (k && v) cookies[k] = decodeURIComponent(v);
    });
    return cookies;
  }

  /**
   * Serialises cookie options into a Set‑Cookie header string.
   *
   * @param {string} name - Cookie name
   * @param {string} value - Cookie value
   * @param {object} options - Cookie options
   * @returns {string} Set‑Cookie header value
   * @private
   */
  _serialize(name, value, options) {
    const parts = [`${name}=${encodeURIComponent(value)}`];
    if (options.maxAge) parts.push(`Max-Age=${options.maxAge}`);
    if (options.path) parts.push(`Path=${options.path}`);
    if (options.domain) parts.push(`Domain=${options.domain}`);
    if (options.httpOnly) parts.push("HttpOnly");
    if (options.secure) parts.push("Secure");
    if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
    return parts.join("; ");
  }
}

module.exports = { ObsidianaCookieManager };
