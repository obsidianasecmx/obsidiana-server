"use strict";

/**
 * Obsidiana Protocol Registration — HTTP handshake endpoints.
 *
 * Registers the handshake routes (`GET /q` and `POST /q`) that implement the
 * full Obsidiana cryptographic handshake over HTTP. The handshake flow:
 *
 * 1. Client requests challenge via GET /q
 * 2. Server responds with PoW challenge + ECDSA signature (identity verification)
 * 3. Client solves PoW, signs challenge with its own key, sends offer via POST /q
 * 4. Server verifies PoW and client signature, completes ECDH handshake
 * 5. Session is stored, ready for encrypted communication
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

// Lazy-loaded ratchet module (optional, for forward secrecy)
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
 * Adds two endpoints:
 * - `GET /q` — Returns PoW challenge signed by server identity
 * - `POST /q` — Accepts client's PoW solution + ECDH public key, completes handshake
 *
 * @param {object} server - Obsidiana server instance
 * @param {ObsidianaSessionStore} store - Session storage
 * @param {ObsidianaPOW} pow - Proof-of-Work manager
 * @param {ObsidianaIdentity} identity - Persistent server identity keypair
 */
function registerProtocol(server, store, pow, identity) {
  /**
   * GET /q — Issue a new PoW challenge.
   *
   * The server generates a challenge with dynamic difficulty based on load,
   * signs it with its identity key, and sends it to the client.
   * The client must verify this signature to ensure the server is authentic.
   */
  server.on("GET", HTTP_HANDSHAKE_PATH, async (req, res) => {
    const challenge = pow.generateChallenge();
    const blob = packChallenge(challenge);

    // Sign challenge with server identity key for client verification
    const blobBytes = new TextEncoder().encode(blob);
    const sig = await identity.sign(blobBytes);
    const wireData = ObsidianaCBOR.encode({ d: blob + "." + sig });
    res.send(200, wireData, { "content-type": "application/cbor" });
  });

  /**
   * POST /q — Complete handshake with client's PoW solution.
   *
   * Steps:
   * 1. Validate request size (max 64KB)
   * 2. Decode and unpack client offer
   * 3. Verify client used the correct server key hash (prevents key confusion)
   * 4. Verify client signature over the challenge (mutual authentication)
   * 5. Verify PoW solution
   * 6. Complete ECDH handshake and derive session key
   * 7. Create optional Double Ratchet for forward secrecy (if available)
   * 8. Store session and respond with handshake completion
   */
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
        publicKey, // Client's ECDH public key
        signerPublicKey, // Client's ECDSA public key (for signature verification)
        challengeId, // PoW challenge ID
        nonce, // PoW solution nonce
        clientSig, // Client's signature over the challenge
        serverKeyHash, // Hash of server's public key (client confirms server identity)
      } = unpacked;

      // Verify client used the expected server key (prevents key confusion attacks)
      const expectedKeyHash = await sha256(identity.publicKey);
      if (serverKeyHash !== expectedKeyHash) {
        console.log("[protocol] Client used wrong server key");
        res.send(401);
        return;
      }

      // Retrieve original challenge blob for signature verification
      const challengeBlob = await getChallengeBlob(pow, challengeId);
      if (!challengeBlob) {
        console.log("[protocol] Client not send challengeBlob");
        res.send(401);
        return;
      }

      // Verify client's signature over the challenge (mutual authentication)
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

      // Verify PoW solution
      const valid = await pow.verify(challengeId, nonce);
      if (!valid) {
        res.send(401);
        return;
      }

      // Complete ECDH handshake
      const hs = new ObsidianaHandshake();
      await hs.init();

      const { response, sessionId } = await hs.complete({
        offer: { d: publicKey },
      });

      // Derive static hint for session lookup (never transmitted)
      const staticHint = await ObsidianaECDSA.deriveStaticHint(sessionId);

      // Optional: Double Ratchet for forward secrecy (if available)
      let ratchet = null;
      if (hs.sharedSecret && DoubleRatchet) {
        ratchet = await DoubleRatchet.create(hs.sharedSecret, licenseKey, 1);
      }

      // Store session with cipher, hint, and optional ratchet
      store.set(sessionId, hs.cipher, staticHint, ratchet);

      // Send handshake response to client
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
