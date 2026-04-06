"use strict";

/**
 * Obsidiana Session Store — In-memory session management with anti-replay.
 *
 * Manages encrypted sessions with TTL (2 hours), HMAC hint lookup,
 * nonce registry for replay protection, and automatic garbage collection.
 *
 * @module session
 * @private
 */

/** Session time-to-live in milliseconds (2 hours). @private */
const SESSION_TTL_MS = 1000 * 60 * 60 * 2;

/** Maximum number of nonces stored before eviction (50,000). @private */
const NONCE_MAX = 50_000;

/**
 * In-memory session store with replay protection.
 */
class ObsidianaSessionStore {
  constructor() {
    /**
     * Session storage.
     * @private
     * @type {Map<string, { cipher: object, createdAt: number, staticHint: string, ratchet: object | null }>}
     */
    this._sessions = new Map();

    /**
     * Nonce registry for replay protection.
     * @private
     * @type {Map<string, number>}
     */
    this._nonces = new Map();

    /**
     * Reverse lookup: static hint (16 hex chars) → sessionId.
     * @private
     * @type {Map<string, string>}
     */
    this._hints = new Map();

    this._cleanup = setInterval(() => this._gc(), 1000 * 60 * 5);
    this._cleanup.unref();
  }

  /**
   * Stores a new session.
   *
   * @param {string} sessionId - Unique session identifier (never transmitted)
   * @param {object} cipher - ObsidianaAES instance for this session
   * @param {string} staticHint - 16 hex chars derived from sessionId via HMAC
   * @param {object} [ratchet=null] - Optional ratchet for forward secrecy
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
   * @param {string} nonce - Nonce from AAD (base64 string)
   * @returns {boolean} `true` if the nonce is new and registered, `false` if it was already used
   */
  claimNonce(nonce) {
    if (this._nonces.has(nonce)) return false;

    if (this._nonces.size >= NONCE_MAX) this._evictOldestNonce();

    this._nonces.set(nonce, Date.now());
    return true;
  }

  /**
   * Finds a session by static hint derived from AAD.
   *
   * @param {object} aad - Additional Authenticated Data object
   * @param {string} aad.hs - Static HMAC hint (16 hex chars)
   * @returns {Promise<{ sessionId: string, cipher: object, ratchet: object | null } | null>}
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
   * Garbage collector — removes expired sessions.
   *
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
   * Evicts the oldest nonce to prevent unbounded memory growth.
   *
   * @private
   */
  _evictOldestNonce() {
    const oldestKey = this._nonces.keys().next().value;
    if (oldestKey !== undefined) this._nonces.delete(oldestKey);
  }
}

module.exports = { ObsidianaSessionStore };
