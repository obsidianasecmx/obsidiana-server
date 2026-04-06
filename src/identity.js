"use strict";

/**
 * Persistent ECDSA P‑256 identity keypair for the server.
 *
 * Generated once on first boot and stored in `.obsidiana/`:
 * - `server.key` – private key in JWK format
 * - `server.pub` – public key as base64 raw P‑256 uncompressed point
 *
 * Used to sign Proof‑of‑Work challenges, allowing clients to verify
 * the server’s authenticity. Completely separate from ephemeral session keys.
 *
 * @module identity
 * @private
 */

const fs = require("fs");
const path = require("path");
const {
  ObsidianaECDSA,
  ObsidianaECDH,
} = require("@obsidianasecmx/obsidiana-protocol");

const IDENTITY_DIR = path.join(process.cwd(), ".obsidiana");
const PRIV_KEY_FILE = path.join(IDENTITY_DIR, "server.key");
const PUB_KEY_FILE = path.join(IDENTITY_DIR, "server.pub");

/**
 * Server identity keypair manager.
 *
 * @example
 * const identity = new ObsidianaIdentity();
 * await identity.init();
 * const signature = await identity.sign(challengeBlob);
 * const pubKey = identity.publicKey;
 */
class ObsidianaIdentity {
  constructor() {
    /** @private {ObsidianaECDSA|null} */
    this._signer = null;

    /** @type {string|null} Base64 raw public key */
    this.publicKey = null;
  }

  /**
   * Loads the identity from disk, or generates a new one.
   *
   * @returns {Promise<this>} This instance for chaining
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
   * Signs data using the identity private key.
   *
   * @param {Buffer | Uint8Array} data - Data to sign
   * @returns {Promise<string>} Base64 signature
   * @throws {Error} If `init()` has not been called
   */
  async sign(data) {
    this._assertLoaded();
    return this._signer.sign(data);
  }

  /**
   * Generates a new keypair and persists it to disk.
   *
   * @private
   */
  async _generate() {
    console.log("[obsidiana] Generating server identity keypair...");

    this._signer = new ObsidianaECDSA();
    await this._signer.generateKeypair();

    this.publicKey = await this._signer.exportPublicKey();

    const privJwk = await crypto.subtle.exportKey(
      "jwk",
      this._signer._keypair.privateKey,
    );

    if (!fs.existsSync(IDENTITY_DIR)) {
      fs.mkdirSync(IDENTITY_DIR, { recursive: true });
    }

    fs.writeFileSync(PRIV_KEY_FILE, JSON.stringify(privJwk), "utf8");
    fs.writeFileSync(PUB_KEY_FILE, this.publicKey, "utf8");

    console.log("[obsidiana] Identity keypair saved to .obsidiana/");
  }

  /**
   * Loads the keypair from disk.
   *
   * @private
   */
  async _load() {
    const privJwk = JSON.parse(fs.readFileSync(PRIV_KEY_FILE, "utf8"));
    this.publicKey = fs.readFileSync(PUB_KEY_FILE, "utf8").trim();

    this._signer = new ObsidianaECDSA();

    const privateKey = await crypto.subtle.importKey(
      "jwk",
      privJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"],
    );

    const pubRaw = ObsidianaECDH.base64ToBuffer(this.publicKey);
    const publicKey = await crypto.subtle.importKey(
      "raw",
      pubRaw,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );

    this._signer._keypair = { privateKey, publicKey };
  }

  /**
   * Throws if the keypair has not been initialised.
   *
   * @private
   * @throws {Error}
   */
  _assertLoaded() {
    if (!this._signer) {
      throw new Error("ObsidianaIdentity: call init() first.");
    }
  }
}

module.exports = { ObsidianaIdentity };
