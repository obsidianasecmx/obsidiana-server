"use strict";

/**
 * In‑memory session store with replay protection.
 *
 * Stores sessions with a TTL of 2 hours. Lookups are performed via a static
 * HMAC hint (16 hex chars) derived from the session ID; the actual session ID
 * is never transmitted.
 *
 * Nonces are permanently tracked to prevent replay attacks. When the nonce
 * limit (50,000) is reached, the oldest nonce is evicted (FIFO).
 *
 * @module session
 * @private
 */

const SESSION_TTL_MS = 1000 * 60 * 60 * 2; // 2 hours
const NONCE_MAX = 50_000;

/**
 * Session store.
 */
class ObsidianaSessionStore {
  constructor() {
    /** @private {Map<string, object>} */
    this._sessions = new Map();

    /** @private {Map<string, number>} */
    this._nonces = new Map();

    /** @private {Map<string, string>} */
    this._hints = new Map();

    setInterval(() => this._gc(), 1000 * 60 * 5).unref();
  }

  /**
   * Stores a new session.
   *
   * @param {string} sessionId - Unique session identifier (never transmitted)
   * @param {object} cipher - ObsidianaAES instance
   * @param {string} staticHint - 16 hex chars derived from sessionId
   * @param {object} [ratchet=null] - Optional ratchet instance
   */
  set(sessionId, cipher, staticHint, ratchet = null) {
    this._sessions.set(sessionId, {
      cipher,
      createdAt: Date.now(),
      staticHint,
      ratchet,
    });
    this._hints.set(staticHint, sessionId);
  }

  /**
   * Checks and registers a nonce for replay protection.
   *
   * @param {string} nonce - Nonce from AAD
   * @returns {boolean} True if the nonce is new and registered
   */
  claimNonce(nonce) {
    if (this._nonces.has(nonce)) return false;

    if (this._nonces.size >= NONCE_MAX) this._evictOldestNonce();

    this._nonces.set(nonce, Date.now());
    return true;
  }

  /**
   * Looks up a session by its static hint (from AAD).
   *
   * @param {object} aad - Additional Authenticated Data
   * @param {string} aad.hs - Static HMAC hint
   * @returns {Promise<object|null>} Session data or null
   */
  async resolveSession(aad) {
    const sessionId = this._hints.get(aad.hs);
    if (!sessionId) return null;

    const entry = this._sessions.get(sessionId);
    if (!entry) return null;

    if (Date.now() - entry.createdAt > SESSION_TTL_MS) return null;

    return {
      sessionId,
      cipher: entry.cipher,
      ratchet: entry.ratchet,
    };
  }

  /**
   * Removes expired sessions.
   * @private
   */
  _gc() {
    const now = Date.now();
    for (const [id, entry] of this._sessions) {
      if (now - entry.createdAt > SESSION_TTL_MS) {
        this._hints.delete(entry.staticHint);
        this._sessions.delete(id);
      }
    }
  }

  /**
   * Evicts the oldest nonce (FIFO).
   * @private
   */
  _evictOldestNonce() {
    const oldestKey = this._nonces.keys().next().value;
    if (oldestKey !== undefined) this._nonces.delete(oldestKey);
  }
}

module.exports = { ObsidianaSessionStore };
