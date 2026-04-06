"use strict";

/**
 * Secure WebSocket with end‑to‑end encryption.
 *
 * Implements the same handshake as HTTP routes (PoW + ECDH + ECDSA)
 * and then encrypts all messages with AES‑GCM‑256.
 *
 * Supports both text and binary messages. The handshake is performed
 * immediately after the WebSocket upgrade.
 *
 * @module ws
 * @private
 */

const { createHash } = require("crypto");
const {
  ObsidianaHandshake,
  ObsidianaCBOR,
  ObsidianaECDSA,
} = require("@obsidianasecmx/obsidiana-protocol");
const { packChallenge, unpackOffer } = require("./pow");

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OP_TEXT = 0x1;
const OP_BINARY = 0x2;
const OP_CLOSE = 0x8;
const OP_PING = 0x9;
const OP_PONG = 0xa;

const MAX_BUFFER_SIZE = 1024 * 1024; // 1 MB

/** @private */
function _concatUint8(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** @private */
function _fromBase64(str) {
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}

/** @private */
function _toBase64(buf) {
  return btoa(String.fromCharCode(...buf));
}

/** @private */
function _normalize(chunk) {
  return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength).slice(
    0,
  );
}

/**
 * WebSocket manager – handles route registration and upgrade.
 */
class ObsidianaWS {
  constructor() {
    /** @private {Map<string, Function>} */
    this._routes = new Map();
    /** @private {ObsidianaSessionStore|null} */
    this._store = null;
    /** @private {ObsidianaPOW|null} */
    this._pow = null;
    /** @private {ObsidianaIdentity|null} */
    this._identity = null;
  }

  /**
   * Initialises the manager with required dependencies.
   *
   * @param {ObsidianaSessionStore} store
   * @param {ObsidianaPOW} pow
   * @param {ObsidianaIdentity} identity
   */
  init(store, pow, identity) {
    this._store = store;
    this._pow = pow;
    this._identity = identity;
  }

  /**
   * Registers a WebSocket route.
   *
   * @param {string} path - Endpoint path
   * @param {Function} handler - (socket, req) => void
   */
  register(path, handler) {
    this._routes.set(path, handler);
  }

  /**
   * Handles an HTTP upgrade request.
   *
   * @param {import("http").IncomingMessage} req
   * @param {import("net").Socket} socket
   * @param {Buffer} head
   */
  handleUpgrade(req, socket, head) {
    const { pathname } = new URL(req.url, "http://x");
    const handler = this._routes.get(pathname);

    if (!handler) {
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }

    const key = req.headers["sec-websocket-key"];
    if (!key) {
      socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      socket.destroy();
      return;
    }

    const acceptKey = createHash("sha1")
      .update(key + WS_GUID)
      .digest("base64");

    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${acceptKey}\r\n` +
        "\r\n",
    );

    const obsidianSocket = new ObsidianaSocket(socket);
    this._runHandshake(obsidianSocket, req, handler, this._identity);
  }

  /**
   * Executes the Obsidiana handshake over the WebSocket.
   *
   * @private
   */
  async _runHandshake(socket, req, handler, identity) {
    const store = this._store;
    const pow = this._pow;

    let cipher = null;
    let sessionId = null;
    let ready = false;
    let ratchet = null;

    const challenge = pow.generateChallenge();
    const blob = packChallenge(challenge);
    const blobBytes = new TextEncoder().encode(blob);
    const sig = identity ? await identity.sign(blobBytes) : null;
    const d = sig ? blob + "." + sig : blob;
    socket.send(ObsidianaCBOR.encode({ d }));

    const timeout = setTimeout(() => {
      if (!ready) socket.close(1008, "Handshake timeout");
    }, 30_000);

    socket.on("close", () => clearTimeout(timeout));

    socket.on("message", async (raw) => {
      if (socket._closed) return;

      const buf =
        raw instanceof Uint8Array ? raw : new TextEncoder().encode(String(raw));

      if (buf.length > MAX_BUFFER_SIZE) {
        socket.close(1009, "message too large");
        return;
      }

      try {
        const msg = ObsidianaCBOR.decode(buf);

        if (!ready) {
          if (!msg?.d || typeof msg.d !== "string") {
            socket.close(1008, "");
            return;
          }

          const unpacked = unpackOffer(msg.d);
          if (!unpacked) {
            socket.close(1008, "");
            return;
          }

          const { publicKey, challengeId, nonce } = unpacked;

          if (challengeId !== challenge.id) {
            socket.close(1008, "");
            return;
          }

          const valid = await pow.verify(challengeId, nonce);
          if (!valid) {
            socket.close(1008, "");
            return;
          }

          const hs = new ObsidianaHandshake();
          await hs.init();

          const result = await hs.complete({ offer: { d: publicKey } });
          cipher = hs.cipher;
          sessionId = result.sessionId;
          ready = true;

          clearTimeout(timeout);

          const staticHint = await ObsidianaECDSA.deriveStaticHint(sessionId);
          ratchet = null;

          store.set(sessionId, cipher, staticHint, ratchet);
          socket._obsidianSessionId = sessionId;
          socket._obsidianCipher = cipher;

          socket.send(ObsidianaCBOR.encode(result.response));

          const _rawSend = socket._rawSend.bind(socket);

          socket.send = async (data) => {
            if (socket._closed) return;
            try {
              let wireData;
              if (socket._lastUseRatchet && ratchet) {
                const { ciphertext, header } = await ratchet.encrypt(data);
                const aadEnvelope = await cipher.encrypt({}, { sessionId });
                wireData = ObsidianaCBOR.encode({
                  d: aadEnvelope.d,
                  ct: _toBase64(ciphertext),
                  hdr: _toBase64(header),
                });
              } else {
                const envelope = await cipher.encrypt(data, { sessionId });
                wireData = ObsidianaCBOR.encode(envelope);
              }
              if (socket._closed) return;
              _rawSend(wireData);
            } catch {
              if (!socket._closed) socket.close(1011, "encrypt error");
            }
          };

          handler(socket, req);
          return;
        }

        // Encrypted message phase
        if (!msg?.d) {
          socket.close(1008, "");
          return;
        }

        const blob = _fromBase64(msg.d);
        const aadLen = (blob[12] << 8) | blob[13];
        const aadBytes = blob.slice(14, 14 + aadLen);
        const aad = JSON.parse(new TextDecoder().decode(aadBytes));

        if (!store.claimNonce(aad.n)) {
          socket.close(1008, "");
          return;
        }

        const isRatchet = !!(msg.ct && msg.hdr && ratchet);
        socket._lastUseRatchet = isRatchet;

        let plain;
        if (isRatchet) {
          const ct = _fromBase64(msg.ct);
          const hdr = _fromBase64(msg.hdr);
          plain = await ratchet.decrypt(ct, hdr);
        } else {
          plain = await cipher.decrypt(msg, { sessionId });
        }

        if (socket._closed) return;
        socket._emit("obsidiana:message", plain);
      } catch (e) {
        console.error("[ws] message error:", e.message);
        if (!socket._closed) socket.close(1008, "");
      }
    });
  }
}

/**
 * WebSocket wrapper handling raw frames and encryption.
 */
class ObsidianaSocket {
  constructor(socket) {
    /** @private {import("net").Socket} */
    this._socket = socket;
    /** @private {boolean} */
    this._closed = false;
    /** @private {Map<string, Function[]>} */
    this._handlers = new Map();
    /** @private {Uint8Array} */
    this._buffer = new Uint8Array(0);
    /** @private {boolean} */
    this._lastUseRatchet = false;

    socket.on("data", (chunk) => this._onData(chunk));
    socket.on("close", () => this._emitClose());
    socket.on("error", (err) => this._emit("error", err));
  }

  /**
   * Registers an event handler.
   *
   * @param {string} event - "message", "obsidiana:message", "close", "error"
   * @param {Function} fn
   * @returns {this}
   */
  on(event, fn) {
    if (!this._handlers.has(event)) this._handlers.set(event, []);
    this._handlers.get(event).push(fn);
    return this;
  }

  /**
   * Sends raw data (used internally for handshake).
   *
   * @param {Uint8Array|object|string} data
   * @private
   */
  _rawSend(data) {
    if (this._closed || !this._socket.writable) return;

    let payload;
    let opcode;

    if (data instanceof Uint8Array) {
      payload = data;
      opcode = OP_BINARY;
    } else if (typeof data === "object" && data !== null) {
      payload = ObsidianaCBOR.encode(data);
      opcode = OP_BINARY;
    } else {
      payload = new TextEncoder().encode(String(data));
      opcode = OP_TEXT;
    }

    this._socket.write(encodeFrame(opcode, payload));
  }

  /**
   * Sends an encrypted message (replaced after handshake).
   *
   * @param {any} data
   */
  send(data) {
    return this._rawSend(data);
  }

  /**
   * Closes the connection.
   *
   * @param {number} [code=1000]
   * @param {string} [reason=""]
   */
  close(code = 1000, reason = "") {
    if (this._closed) return;
    this._closed = true;
    const reasonBytes = new TextEncoder().encode(reason);
    const payload = new Uint8Array(2 + reasonBytes.length);
    new DataView(payload.buffer).setUint16(0, code);
    payload.set(reasonBytes, 2);
    this._socket.write(encodeFrame(OP_CLOSE, payload));
    this._socket.end();
  }

  /**
   * Emits an event.
   *
   * @param {string} event
   * @param {...any} args
   * @private
   */
  _emit(event, ...args) {
    const fns = this._handlers.get(event) ?? [];
    for (const fn of fns) fn(...args);
  }

  /** @private */
  _emitClose() {
    if (this._closed) return;
    this._closed = true;
    this._emit("close");
  }

  /** @private */
  _onData(chunk) {
    this._buffer = _concatUint8(this._buffer, _normalize(chunk));

    if (this._buffer.length > MAX_BUFFER_SIZE) {
      this.close(1009, "message too large");
      return;
    }

    while (this._buffer.length >= 2) {
      const frame = decodeFrame(this._buffer);
      if (!frame) break;
      this._buffer = this._buffer.slice(frame.consumed);
      this._handleFrame(frame);
    }
  }

  /** @private */
  _handleFrame(frame) {
    switch (frame.opcode) {
      case OP_TEXT:
        this._emit("message", new TextDecoder().decode(frame.payload));
        break;
      case OP_BINARY:
        this._emit("message", frame.payload);
        break;
      case OP_PING:
        this._socket.write(encodeFrame(OP_PONG, frame.payload));
        break;
      case OP_CLOSE:
        this._socket.write(encodeFrame(OP_CLOSE, frame.payload));
        this._socket.end();
        this._emitClose();
        break;
    }
  }
}

/**
 * Encodes a WebSocket frame.
 *
 * @param {number} opcode
 * @param {Uint8Array} payload
 * @returns {Uint8Array}
 * @private
 */
function encodeFrame(opcode, payload) {
  const len = payload.length;
  let header;

  if (len < 126) {
    header = new Uint8Array(2);
    header[0] = 0x80 | opcode;
    header[1] = len;
  } else if (len < 65536) {
    header = new Uint8Array(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    new DataView(header.buffer).setUint16(2, len);
  } else {
    header = new Uint8Array(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    new DataView(header.buffer).setBigUint64(2, BigInt(len));
  }

  return _concatUint8(header, payload);
}

/**
 * Decodes a WebSocket frame from a buffer.
 *
 * @param {Uint8Array} buf
 * @returns {object|null} { opcode, payload, consumed }
 * @private
 */
function decodeFrame(buf) {
  if (buf.length < 2) return null;

  const clean = buf.byteOffset !== 0 ? buf.slice(0) : buf;
  const view = new DataView(clean.buffer);

  const opcode = clean[0] & 0x0f;
  const masked = (clean[1] & 0x80) !== 0;
  let payloadLen = clean[1] & 0x7f;
  let offset = 2;

  if (payloadLen === 126) {
    if (clean.length < 4) return null;
    payloadLen = view.getUint16(2);
    offset = 4;
  } else if (payloadLen === 127) {
    if (clean.length < 10) return null;
    payloadLen = Number(view.getBigUint64(2));
    offset = 10;
  }

  if (masked) {
    if (clean.length < offset + 4 + payloadLen) return null;
    const mask = clean.slice(offset, offset + 4);
    offset += 4;
    const payload = new Uint8Array(payloadLen);
    for (let i = 0; i < payloadLen; i++) {
      payload[i] = clean[offset + i] ^ mask[i % 4];
    }
    return { opcode, payload, consumed: offset + payloadLen };
  }

  if (clean.length < offset + payloadLen) return null;
  const payload = clean.slice(offset, offset + payloadLen);
  return { opcode, payload, consumed: offset + payloadLen };
}

module.exports = { ObsidianaWS };
