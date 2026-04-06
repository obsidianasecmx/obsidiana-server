"use strict";

/**
 * Obsidiana Protocol Registration — HTTP handshake endpoints.
 *
 * Registers the handshake routes (`GET /q` and `POST /q`) that implement the
 * full Obsidiana cryptographic handshake over HTTP.
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

/** HTTP path for handshake endpoints. @public */
const HTTP_HANDSHAKE_PATH = "/q";

/**
 * Computes SHA-256 hash of a string and returns hex digest.
 *
 * @param {string} str - Input string
 * @returns {Promise<string>} Hex digest (64 chars)
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
 * Registers the handshake routes on the Obsidiana server.
 *
 * @param {object} server - Obsidiana server instance
 * @param {ObsidianaSessionStore} store - Session storage
 * @param {ObsidianaPOW} pow - Proof-of-Work manager
 * @param {ObsidianaIdentity} identity - Persistent server identity keypair
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
      const pubKeyBytes = signerPublicKey;
      const sigBytes = clientSig;

      const validSig = await ObsidianaECDSA.verify(
        pubKeyBytes,
        blobBytes,
        sigBytes,
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
