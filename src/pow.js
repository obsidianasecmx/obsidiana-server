"use strict";

/**
 * Proof‑of‑Work manager with dynamic difficulty.
 *
 * Implements a client‑side SHA‑256 PoW challenge to prevent handshake flooding.
 * Difficulty adjusts based on request rate: higher load → harder challenges.
 *
 * Challenge lifecycle:
 * 1. Server generates random hash + difficulty, stores challenge.
 * 2. Client finds nonce such that SHA‑256(hash + nonce) has `difficulty` leading zero bits.
 * 3. Server verifies solution and marks challenge as used.
 *
 * @module pow
 * @private
 */

/** @private */
const POW_DEFAULTS = {
  min: 2,
  max: 8,
  window: 10,
  challengeTTL: 30,
};

/**
 * PoW manager.
 *
 * @example
 * const pow = new ObsidianaPOW();
 * const challenge = pow.generateChallenge();
 * // client solves ...
 * const ok = await pow.verify(challenge.id, nonce);
 */
class ObsidianaPOW {
  /**
   * @param {object} [options] - Configuration
   * @param {number} [options.min=2] - Minimum difficulty (leading zero bits)
   * @param {number} [options.max=8] - Maximum difficulty under load
   * @param {number} [options.window=10] - Window (seconds) to measure request rate
   * @param {number} [options.challengeTTL=30] - Seconds before a challenge expires
   */
  constructor(options = {}) {
    this._cfg = { ...POW_DEFAULTS, ...options };

    /** @private {Map<string, object>} */
    this._challenges = new Map();

    /** @private {number[]} */
    this._requests = [];

    setInterval(() => this._gc(), 30_000).unref();
  }

  /**
   * Generates a new challenge.
   *
   * @returns {{ id: string, hash: string, difficulty: number, ttl: number }}
   */
  generateChallenge() {
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
   * Verifies a client’s PoW solution.
   *
   * @param {string} challengeId - ID of the challenge
   * @param {string} nonce - Nonce found by the client
   * @returns {Promise<boolean>} True if valid and unused
   */
  async verify(challengeId, nonce) {
    const entry = this._challenges.get(challengeId);
    if (!entry) return false;
    if (entry.used) return false;

    const age = (Date.now() - entry.createdAt) / 1000;
    if (age > this._cfg.challengeTTL) {
      this._challenges.delete(challengeId);
      return false;
    }

    const input = entry.hash + nonce;
    const digest = await _sha256Hex(input);
    const valid = _checkLeadingZeros(digest, entry.difficulty);

    if (valid) {
      entry.used = true;
      return true;
    } else {
      this._challenges.delete(challengeId);
      return false;
    }
  }

  /**
   * Computes current difficulty based on request rate.
   *
   * @returns {number}
   * @private
   */
  _currentDifficulty() {
    const { min, max, window: win } = this._cfg;
    const rate = this._requests.length;
    const ratio = Math.min(rate / 20, 1);
    return Math.round(min + ratio * (max - min));
  }

  /**
   * Removes requests older than the window.
   * @private
   */
  _pruneRequests() {
    const cutoff = Date.now() - this._cfg.window * 1000;
    this._requests = this._requests.filter((ts) => ts > cutoff);
  }

  /**
   * Garbage collector for expired challenges.
   * @private
   */
  _gc() {
    const now = Date.now();
    for (const [id, entry] of this._challenges) {
      const age = (now - entry.createdAt) / 1000;
      if (age > this._cfg.challengeTTL + 5) {
        this._challenges.delete(id);
      }
    }
  }
}

/**
 * Generates a random hex string.
 *
 * @param {number} bytes - Number of random bytes
 * @returns {string}
 * @private
 */
function _randomHex(bytes) {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Computes SHA‑256 of a string and returns hex.
 *
 * @param {string} input
 * @returns {Promise<string>}
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
 * @param {string} hex - 64‑character hex digest
 * @param {number} difficulty - Required leading zero bits
 * @returns {boolean}
 * @private
 */
function _checkLeadingZeros(hex, difficulty) {
  const fullChars = Math.floor(difficulty / 4);
  const remainder = difficulty % 4;

  for (let i = 0; i < fullChars; i++) {
    if (hex[i] !== "0") return false;
  }

  if (remainder > 0) {
    const val = parseInt(hex[fullChars], 16);
    const mask = 0xf >> remainder;
    if (val > mask) return false;
  }

  return true;
}

/**
 * Packs a challenge into a compact base64 blob.
 *
 * Wire format: id (32 bytes) + difficulty (1) + ttl (2) + hash (64 bytes)
 *
 * @param {object} challenge - Challenge object
 * @returns {string} Base64‑encoded blob
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
 * @param {string} b64 - Base64 challenge
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
 * Unpacks a client offer blob (PoW solution + ECDH keys).
 *
 * @param {string} b64 - Base64 offer
 * @returns {object|null} Decoded offer or null on error
 */
function unpackOffer(b64) {
  try {
    const bin = atob(b64);
    const buf = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    let offset = 0;

    const ecdhLen = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    const publicKey = new TextDecoder().decode(
      buf.slice(offset, offset + ecdhLen),
    );
    offset += ecdhLen;

    const signerLen = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    const signerPublicKey = new TextDecoder().decode(
      buf.slice(offset, offset + signerLen),
    );
    offset += signerLen;

    const cidLen = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    const challengeId = new TextDecoder().decode(
      buf.slice(offset, offset + cidLen),
    );
    offset += cidLen;

    const nLen = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    const nonce = new TextDecoder().decode(buf.slice(offset, offset + nLen));
    offset += nLen;

    const sigLen = (buf[offset] << 8) | buf[offset + 1];
    offset += 2;
    const clientSig = new TextDecoder().decode(
      buf.slice(offset, offset + sigLen),
    );
    offset += sigLen;

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
 * Retrieves the original challenge blob for a given challenge ID.
 *
 * @param {ObsidianaPOW} pow - PoW instance
 * @param {string} challengeId - Challenge ID
 * @returns {Promise<string|null>} Base64 challenge blob or null
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
