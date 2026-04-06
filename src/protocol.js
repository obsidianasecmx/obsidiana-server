"use strict";

/**
 * Handshake protocol registration (HTTP endpoints `/q`).
 *
 * Implements the full Obsidiana cryptographic handshake over HTTP:
 * - GET /q: returns a PoW challenge signed by the server identity.
 * - POST /q: accepts client’s PoW solution, ECDH public key, and signatures,
 *            completes ECDH, derives session key, and stores the session.
 *
 * @module protocol
 * @private
 */

const {
  ObsidianaHandshake,
  ObsidianaCBOR,
  ObsidianaECDSA,
} = require("@obsidianasecmx/obsidiana-protocol");
const { packChallenge, unpackOffer, getChallengeBlob } = require("./pow");

let DoubleRatchet = null;

/** @public */
const HTTP_HANDSHAKE_PATH = "/q";

/**
 * SHA‑256 hash of a string, returns hex.
 *
 * @param {string} str
 * @returns {Promise<string>}
 * @private
 */
async function sha256(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Registers handshake routes on the server.
 *
 * @param {object} server - Obsidiana server instance
 * @param {ObsidianaSessionStore} store - Session store
 * @param {ObsidianaPOW} pow - PoW manager
 * @param {ObsidianaIdentity} identity - Server identity keypair
 */
function registerProtocol(server, store, pow, identity) {
  server.on("GET", HTTP_HANDSHAKE_PATH, async (req, res) => {
    const challenge = pow.generateChallenge();
    const blob = packChallenge(challenge);
    const blobBytes = new TextEncoder().encode(blob);
    const sig = await identity.sign(blobBytes);
    const wireData = ObsidianaCBOR.encode({ d: blob + "." + sig });
    res.send(200, wireData, { "content-type": "application/cbor" });
  });

  server.on("POST", HTTP_HANDSHAKE_PATH, async (req, res) => {
    const MAX_HANDSHAKE_SIZE = 64 * 1024;

    try {
      const raw = await req.rawBody();

      if (raw.length > MAX_HANDSHAKE_SIZE) {
        res.send(413);
        return;
      }

      const body = ObsidianaCBOR.decode(raw);

      if (!body?.d || typeof body.d !== "string") {
        res.send(400);
        return;
      }

      const unpacked = unpackOffer(body.d);
      if (!unpacked) {
        res.send(400);
        return;
      }

      const {
        publicKey,
        signerPublicKey,
        challengeId,
        nonce,
        clientSig,
        serverKeyHash,
      } = unpacked;

      const expectedKeyHash = await sha256(identity.publicKey);
      if (serverKeyHash !== expectedKeyHash) {
        console.log("[protocol] Client used wrong server key");
        res.send(401);
        return;
      }

      const challengeBlob = await getChallengeBlob(pow, challengeId);
      if (!challengeBlob) {
        console.log("[protocol] Client not send challengeBlob");
        res.send(401);
        return;
      }

      const blobBytes = new TextEncoder().encode(challengeBlob);
      const validSig = await ObsidianaECDSA.verify(
        signerPublicKey,
        blobBytes,
        clientSig,
      );

      if (!validSig) {
        console.log("[protocol] Client signature invalid");
        res.send(401);
        return;
      }

      const valid = await pow.verify(challengeId, nonce);
      if (!valid) {
        res.send(401);
        return;
      }

      const hs = new ObsidianaHandshake();
      await hs.init();

      const { response, sessionId } = await hs.complete({
        offer: { d: publicKey },
      });

      const staticHint = await ObsidianaECDSA.deriveStaticHint(sessionId);

      let ratchet = null;
      if (hs.sharedSecret && DoubleRatchet) {
        ratchet = await DoubleRatchet.create(hs.sharedSecret, licenseKey, 1);
      }

      store.set(sessionId, hs.cipher, staticHint, ratchet);

      const wireResponse = ObsidianaCBOR.encode(response);
      res.send(200, wireResponse, { "content-type": "application/cbor" });
    } catch (err) {
      console.error("[protocol] error:", err);
      res.send(400);
    }
  });
}

module.exports = {
  registerProtocol,
  HTTP_HANDSHAKE_PATH,
};
