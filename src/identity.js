"use strict";

/**
 * Obsidiana Identity — Persistent ECDSA P-256 identity keypair for the server.
 *
 * This identity keypair is generated once on first server boot and persists
 * across restarts. It is used to sign Proof-of-Work challenges, allowing
 * clients to verify the server's authenticity before investing CPU cycles.
 *
 * This is completely separate from the ephemeral session signer (ObsidianaECDSA
 * used for per-message AAD). The identity keypair is long-lived and should
 * be treated as a root of trust for the server.
 *
 * Keys are stored in `.obsidiana/` directory:
 * - `server.key` — private key in JWK format (JSON)
 * - `server.pub` — public key as base64-encoded raw P-256 uncompressed point
 *
 * @module identity
 * @private
 */

const fs = require("fs");
const path = require("path");
const { ObsidianaECDSA, ObsidianaECDH } = require("@obsidianasecmx/obsidiana-protocol");

// Directory and file paths for key storage
const IDENTITY_DIR = path.join(process.cwd(), ".obsidiana");
const PRIV_KEY_FILE = path.join(IDENTITY_DIR, "server.key");
const PUB_KEY_FILE = path.join(IDENTITY_DIR, "server.pub");

/**
 * Persistent ECDSA P-256 identity keypair for the server.
 *
 * The identity keypair serves as the server's long-term cryptographic identity.
 * It is generated once on first boot and reused across restarts. Clients embed
 * the server's public key (or its hash) to verify that they are communicating
 * with the expected server.
 *
 * @example
 * const identity = new ObsidianaIdentity();
 * await identity.init(); // loads or generates keys
 *
 * // Sign a challenge using ObsidianaECDSA
 * const challengeBlob = new TextEncoder().encode(challenge);
 * const signature = await identity.sign(challengeBlob);
 *
 * // Export public key for client distribution
 * const publicKey = identity.publicKey; // base64 string
 */
class ObsidianaIdentity {
  constructor() {
    /**
     * The loaded ECDSA signer instance.
     * @private
     * @type {ObsidianaECDSA | null}
     */
    this._signer = null;

    /**
     * Base64-encoded raw P-256 uncompressed public key (65 bytes: 0x04 || x || y).
     * @type {string | null}
     */
    this.publicKey = null;
  }

  /**
   * Loads the identity keypair from disk, or generates and persists a new one.
   *
   * If keys already exist in `.obsidiana/`, they are loaded. Otherwise, a new
   * keypair is generated, saved to disk, and loaded.
   *
   * @returns {Promise<this>} Current instance for method chaining
   */
  async init() {
    if (fs.existsSync(PRIV_KEY_FILE) && fs.existsSync(PUB_KEY_FILE)) {
      await this._load();
    } else {
      await this._generate();
    }
    return this;
  }

  /**
   * Signs raw data with the identity private key.
   *
   * Uses `ObsidianaECDSA.sign()` internally. Returns the signature as a
   * base64-encoded string.
   *
   * @param {Buffer | Uint8Array} data - Data to sign
   * @returns {Promise<string>} Base64-encoded signature
   * @throws {Error} If `init()` has not been called
   */
  async sign(data) {
    this._assertLoaded();
    return this._signer.sign(data);
  }

  /**
   * Generates a new identity keypair and persists it to disk.
   *
   * Uses `ObsidianaECDSA.generateKeypair()` to create the keys.
   *
   * @private
   */
  async _generate() {
    console.log("[obsidiana] Generating server identity keypair...");

    // Create new ECDSA signer and generate keypair
    this._signer = new ObsidianaECDSA();
    await this._signer.generateKeypair();

    // Export public key as base64
    this.publicKey = await this._signer.exportPublicKey();

    // Export private key as JWK for persistence
    const privJwk = await crypto.subtle.exportKey(
      "jwk",
      this._signer._keypair.privateKey,
    );

    // Ensure directory exists
    if (!fs.existsSync(IDENTITY_DIR)) {
      fs.mkdirSync(IDENTITY_DIR, { recursive: true });
    }

    // Write keys to disk
    fs.writeFileSync(PRIV_KEY_FILE, JSON.stringify(privJwk), "utf8");
    fs.writeFileSync(PUB_KEY_FILE, this.publicKey, "utf8");

    console.log("[obsidiana] Identity keypair saved to .obsidiana/");
  }

  /**
   * Loads identity keypair from disk.
   *
   * Reconstructs the `ObsidianaECDSA` instance from stored keys.
   *
   * @private
   */
  async _load() {
    const privJwk = JSON.parse(fs.readFileSync(PRIV_KEY_FILE, "utf8"));
    this.publicKey = fs.readFileSync(PUB_KEY_FILE, "utf8").trim();

    // Create ECDSA signer and import private key from JWK
    this._signer = new ObsidianaECDSA();

    // Import private key directly into the signer's internal keypair
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      privJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"],
    );

    // Import public key from raw base64
    const pubRaw = ObsidianaECDH.base64ToBuffer(this.publicKey);
    const publicKey = await crypto.subtle.importKey(
      "raw",
      pubRaw,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );

    // Set the keypair on the signer
    this._signer._keypair = { privateKey, publicKey };
  }

  /**
   * Asserts that the keypair has been loaded.
   *
   * @private
   * @throws {Error} If `init()` has not been called
   */
  _assertLoaded() {
    if (!this._signer) {
      throw new Error("ObsidianaIdentity: call init() first.");
    }
  }
}

module.exports = { ObsidianaIdentity };
