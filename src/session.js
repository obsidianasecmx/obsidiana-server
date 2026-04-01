"use strict";

/**
 * Obsidiana Session Store — In-memory session management with anti-replay.
 *
 * Manages encrypted sessions with:
 * - Session storage with TTL (2 hours)
 * - HMAC hint lookup (sessionId never transmitted)
 * - Nonce registry for replay protection (nonces never expire)
 * - Automatic garbage collection
 *
 * The store is ephemeral — sessions are lost on server restart.
 * For production, consider a Redis backend.
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
 *
 * Sessions are stored by sessionId, but lookups are performed via static HMAC
 * hints (16 hex chars). The actual sessionId is never transmitted over the wire.
 *
 * Nonce tracking is permanent — once a nonce is used, it can never be reused.
 * This provides strong replay protection at the cost of memory. Old nonces are
 * evicted using FIFO (oldest first) when the limit is reached.
 *
 * @example
 * const store = new ObsidianaSessionStore();
 *
 * // Store a session after handshake
 * store.set(sessionId, cipher, staticHint);
 *
 * // Look up session from AAD hint
 * const session = await store.resolveSession({ hs: aad.hs });
 *
 * // Prevent replay attacks
 * const isNew = store.claimNonce(aad.n);
 * if (!isNew) return reject();
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
     * Keys are nonce strings, values are timestamps (for debugging).
     * Nonces never expire — once used, they are permanently banned.
     * @private
     * @type {Map<string, number>}
     */
    this._nonces = new Map();

    /**
     * Reverse lookup: static hint (16 hex chars) → sessionId.
     * Allows O(1) session lookup without exposing the sessionId.
     * @private
     * @type {Map<string, string>}
     */
    this._hints = new Map();

    // Periodic cleanup every 5 minutes
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
   * Nonces are permanently banned once used. If the nonce limit (`NONCE_MAX`)
   * is reached, the oldest nonce is evicted (FIFO) to prevent unbounded growth.
   *
   * @param {string} nonce - Nonce from AAD (base64 string)
   * @returns {boolean} `true` if the nonce is new and registered, `false` if it was already used
   */
  claimNonce(nonce) {
    // Reject if nonce already used
    if (this._nonces.has(nonce)) return false;

    // Evict oldest nonce if we're at capacity
    if (this._nonces.size >= NONCE_MAX) this._evictOldestNonce();

    // Register the nonce
    this._nonces.set(nonce, Date.now());
    return true;
  }

  /**
   * Finds a session by static hint derived from AAD.
   *
   * The static hint (`aad.hs`) is the only session identifier ever transmitted.
   * It's mathematically impossible to reverse back to the original sessionId.
   *
   * @param {object} aad - Additional Authenticated Data object
   * @param {string} aad.hs - Static HMAC hint (16 hex chars)
   * @returns {Promise<{ sessionId: string, cipher: object, ratchet: object | null } | null>}
   *          Session data if found and not expired, otherwise null
   */
  async resolveSession(aad) {
    // Look up sessionId by static hint
    const sessionId = this._hints.get(aad.hs);
    if (!sessionId) return null;

    const entry = this._sessions.get(sessionId);
    if (!entry) return null;

    // Check TTL expiration
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
   * Runs every 5 minutes automatically. Sessions older than `SESSION_TTL_MS`
   * are deleted from both `_sessions` and `_hints` maps.
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
   * JavaScript Maps preserve insertion order, so the first key (obtained via
   * `keys().next().value`) is always the oldest. This provides O(1) eviction.
   *
   * @private
   */
  _evictOldestNonce() {
    const oldestKey = this._nonces.keys().next().value;
    if (oldestKey !== undefined) this._nonces.delete(oldestKey);
  }
}

module.exports = { ObsidianaSessionStore };
