"use strict";

/**
 * Obsidiana Proof of Work — Dynamic difficulty DoS protection.
 *
 * Implements a client-side Proof of Work (PoW) challenge system to prevent
 * handshake flooding attacks. Difficulty adjusts dynamically based on request
 * rate: higher load = harder challenges.
 *
 * The PoW algorithm uses SHA-256: client must find a nonce such that
 * SHA-256(hash + nonce) starts with `difficulty` leading zero bits.
 *
 * The handshake flow:
 * 1. Server sends PoW challenge + ECDSA signature (server identity verification)
 * 2. Client verifies server signature, solves PoW, sends offer with client signature
 * 3. Server verifies PoW and client signature, completes ECDH handshake
 *
 * @module pow
 * @private
 */

/** Default PoW configuration. @private */
const POW_DEFAULTS = {
  min: 2, // Minimum difficulty (leading zero bits)
  max: 8, // Maximum difficulty under load
  window: 10, // Time window in seconds to measure request rate
  challengeTTL: 30, // Seconds before a challenge expires
};

/**
 * Proof of Work manager with dynamic difficulty.
 *
 * Generates challenges, tracks request rate for difficulty adjustment,
 * and verifies client solutions before allowing handshake completion.
 *
 * Challenge lifecycle:
 * 1. Server generates challenge with random hash and difficulty
 * 2. Server signs challenge with identity key (client verifies)
 * 3. Client solves by finding nonce that produces leading zeros
 * 4. Client signs offer with its own key (mutual authentication)
 * 5. Server verifies solution and client signature, marks challenge as used
 *
 * @example
 * const pow = new ObsidianaPOW();
 *
 * // Generate challenge for client
 * const challenge = pow.generateChallenge();
 * // { id: "a1b2c3...", hash: "def456...", difficulty: 4, ttl: 30 }
 *
 * // Client sends solution (challengeId + nonce + signatures)
 * const isValid = await pow.verify(challengeId, nonce);
 */
class ObsidianaPOW {
  /**
   * Creates a new PoW manager.
   *
   * @param {object} [options] - Configuration options
   * @param {number} [options.min=2] - Minimum difficulty (leading zero bits)
   * @param {number} [options.max=8] - Maximum difficulty under load
   * @param {number} [options.window=10] - Time window (seconds) to measure request rate
   * @param {number} [options.challengeTTL=30] - Seconds before a challenge expires
   */
  constructor(options = {}) {
    this._cfg = { ...POW_DEFAULTS, ...options };

    /**
     * Active challenges.
     * @private
     * @type {Map<string, { hash: string, difficulty: number, createdAt: number, used: boolean, attempts: number }>}
     */
    this._challenges = new Map();

    /**
     * Timestamps of recent challenge requests for rate calculation.
     * @private
     * @type {number[]}
     */
    this._requests = [];

    // Cleanup expired challenges every 30 seconds
    this._cleanup = setInterval(() => this._gc(), 30_000);
    this._cleanup.unref();
  }

  /**
   * Generates a new challenge for the client to solve.
   *
   * Difficulty is adjusted dynamically based on recent request rate.
   * Higher request rate → higher difficulty → more client CPU work.
   *
   * @returns {{ id: string, hash: string, difficulty: number, ttl: number }}
   *          Challenge object to send to client
   */
  generateChallenge() {
    // Track request for rate calculation
    this._requests.push(Date.now());
    this._pruneRequests();

    const difficulty = this._currentDifficulty();
    const id = _randomHex(16);
    const hash = _randomHex(32);

    this._challenges.set(id, {
      hash,
      difficulty,
      createdAt: Date.now(),
      used: false,
      attempts: 0,
    });

    return {
      id,
      hash,
      difficulty,
      ttl: this._cfg.challengeTTL,
    };
  }

  /**
   * Verifies a client's PoW solution.
   *
   * Checks:
   * - Challenge exists and hasn't expired
   * - Challenge hasn't been used before
   * - SHA-256(hash + nonce) has required leading zero bits
   *
   * @param {string} challengeId - ID of the challenge to verify
   * @param {string} nonce - Client-provided nonce that satisfies the difficulty
   * @returns {Promise<boolean>} True if solution is valid and challenge was unused
   */
  async verify(challengeId, nonce) {
    const entry = this._challenges.get(challengeId);
    if (!entry) return false;
    if (entry.used) return false;

    // TTL check
    const age = (Date.now() - entry.createdAt) / 1000;
    if (age > this._cfg.challengeTTL) {
      this._challenges.delete(challengeId);
      return false;
    }

    // Verify PoW: SHA-256(hash + nonce) must start with `difficulty` zero bits
    const input = entry.hash + nonce;
    const digest = await _sha256Hex(input);
    const valid = _checkLeadingZeros(digest, entry.difficulty);

    if (valid) {
      entry.used = true;
      return true;
    } else {
      // Invalid solution — delete challenge to prevent brute force
      this._challenges.delete(challengeId);
      return false;
    }
  }

  /**
   * Calculates current difficulty based on recent request rate.
   *
   * Higher request rate = higher difficulty (linear interpolation between
   * min and max). Rate is capped at 20 requests per window for max difficulty.
   *
   * @returns {number} Difficulty (leading zero bits)
   * @private
   */
  _currentDifficulty() {
    const { min, max, window: win } = this._cfg;
    const rate = this._requests.length;
    const ratio = Math.min(rate / 20, 1);
    return Math.round(min + ratio * (max - min));
  }

  /**
   * Removes request timestamps older than the configured window.
   * @private
   */
  _pruneRequests() {
    const cutoff = Date.now() - this._cfg.window * 1000;
    this._requests = this._requests.filter((ts) => ts > cutoff);
  }

  /**
   * Garbage collector — removes expired challenges.
   * Runs every 30 seconds automatically.
   * @private
   */
  _gc() {
    const now = Date.now();
    for (const [id, entry] of this._challenges) {
      const age = (now - entry.createdAt) / 1000;
      // Keep challenges for 5 seconds beyond TTL for grace period
      if (age > this._cfg.challengeTTL + 5) {
        this._challenges.delete(id);
      }
    }
  }
}

/**
 * Generates a random hex string.
 * @param {number} bytes - Number of random bytes
 * @returns {string} Hex string of length `bytes * 2`
 * @private
 */
function _randomHex(bytes) {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Computes SHA-256 hash of a string and returns it as hex.
 * @param {string} input - Input string
 * @returns {Promise<string>} Hex digest (64 chars)
 * @private
 */
async function _sha256Hex(input) {
  const encoded = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(buf), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

/**
 * Checks if a hex digest has at least `difficulty` leading zero bits.
 *
 * @param {string} hex - Hex digest (64 chars)
 * @param {number} difficulty - Required leading zero bits
 * @returns {boolean} True if condition satisfied
 * @private
 */
function _checkLeadingZeros(hex, difficulty) {
  const fullChars = Math.floor(difficulty / 4);
  const remainder = difficulty % 4;

  // Check full zero characters
  for (let i = 0; i < fullChars; i++) {
    if (hex[i] !== "0") return false;
  }

  // Check partial character (remaining bits)
  if (remainder > 0) {
    const val = parseInt(hex[fullChars], 16);
    const mask = 0xf >> remainder;
    if (val > mask) return false;
  }

  return true;
}

/**
 * Packs a challenge into a compact base64 string for transmission.
 *
 * Wire format:
 * ┌──────────────┬──────────────┬──────────────┬──────────────┐
 * │ id (32 bytes)│ difficulty(1)│ ttl (2 bytes)│ hash (64 bytes)│
 * └──────────────┴──────────────┴──────────────┴──────────────┘
 *
 * @param {object} challenge - Challenge object
 * @param {string} challenge.id - 32-byte hex ID
 * @param {string} challenge.hash - 64-byte hex hash
 * @param {number} challenge.difficulty - Difficulty value (1 byte)
 * @param {number} challenge.ttl - Time-to-live in seconds (2 bytes)
 * @returns {string} Base64-encoded challenge blob
 */
function packChallenge(challenge) {
  const idBytes = new TextEncoder().encode(challenge.id);
  const hashBytes = new TextEncoder().encode(challenge.hash);
  const buf = new Uint8Array(idBytes.length + 1 + 2 + hashBytes.length);
  let offset = 0;

  buf.set(idBytes, offset);
  offset += idBytes.length;

  buf[offset] = challenge.difficulty;
  offset += 1;

  buf[offset] = (challenge.ttl >> 8) & 0xff;
  buf[offset + 1] = challenge.ttl & 0xff;
  offset += 2;

  buf.set(hashBytes, offset);

  return btoa(String.fromCharCode(...buf));
}

/**
 * Unpacks a base64 challenge blob.
 *
 * @param {string} b64 - Base64-encoded challenge blob
 * @returns {{ id: string, hash: string, difficulty: number, ttl: number }}
 * @throws {Error} If unpacking fails
 */
function unpackChallenge(b64) {
  const bin = atob(b64);
  const buf = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  const ID_LEN = 32;
  const HASH_LEN = 64;
  let offset = 0;

  const id = new TextDecoder().decode(buf.slice(offset, offset + ID_LEN));
  offset += ID_LEN;

  const difficulty = buf[offset];
  offset += 1;

  const ttl = (buf[offset] << 8) | buf[offset + 1];
  offset += 2;

  const hash = new TextDecoder().decode(buf.slice(offset, offset + HASH_LEN));

  return { id, hash, difficulty, ttl };
}

/**
 * Unpacks a client offer blob.
 *
 * @param {string} b64 - Base64-encoded offer blob
 * @returns {{
 *   publicKey: string,
 *   signerPublicKey: string,
 *   challengeId: string,
 *   nonce: string,
 *   clientSig: string,
 *   serverKeyHash: string
 * } | null} Decoded offer or null on error
 */
function unpackOffer(b64) {
  try {
    const bin = atob(b64);
    const buf = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    let offset = 0;

    // ecdhPublicKey
    const ecdhLen = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    const publicKey = new TextDecoder().decode(
      buf.slice(offset, offset + ecdhLen),
    );
    offset += ecdhLen;

    // signerPublicKey
    const signerLen = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    const signerPublicKey = new TextDecoder().decode(
      buf.slice(offset, offset + signerLen),
    );
    offset += signerLen;

    // challengeId
    const cidLen = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    const challengeId = new TextDecoder().decode(
      buf.slice(offset, offset + cidLen),
    );
    offset += cidLen;

    // nonce
    const nLen = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    const nonce = new TextDecoder().decode(buf.slice(offset, offset + nLen));
    offset += nLen;

    // clientSig
    const sigLen = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    const clientSig = new TextDecoder().decode(
      buf.slice(offset, offset + sigLen),
    );
    offset += sigLen;

    // serverKeyHash
    const skhLen = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    const serverKeyHash = new TextDecoder().decode(
      buf.slice(offset, offset + skhLen),
    );

    return {
      publicKey,
      signerPublicKey,
      challengeId,
      nonce,
      clientSig,
      serverKeyHash,
    };
  } catch (err) {
    console.error("[pow] unpackOffer error:", err.message);
    return null;
  }
}

/**
 * Retrieves the original challenge blob for signature verification.
 *
 * @param {ObsidianaPOW} pow - PoW instance
 * @param {string} challengeId - Challenge ID
 * @returns {Promise<string|null>} Base64 challenge blob or null if not found
 */
async function getChallengeBlob(pow, challengeId) {
  const entry = pow._challenges.get(challengeId);
  if (!entry) return null;

  const challenge = {
    id: challengeId,
    hash: entry.hash,
    difficulty: entry.difficulty,
    ttl: pow._cfg.challengeTTL,
  };
  return packChallenge(challenge);
}

module.exports = {
  ObsidianaPOW,
  packChallenge,
  unpackChallenge,
  unpackOffer,
  getChallengeBlob,
};
