/**
 * Binary protocol for e2hat encrypted chat.
 * JavaScript mirror of server/protocol.py — both must stay in sync.
 *
 * Frame format:
 *   [MSG_TYPE: 1 byte] [PAYLOAD_LEN: 2 bytes big-endian] [PAYLOAD: N bytes]
 *
 * Compressed elliptic curve point (secp521r1):
 *   [X coordinate: 66 bytes big-endian] [PARITY: 1 byte] = 67 bytes total
 *
 * All multi-byte integers are big-endian. Session IDs are 4 bytes.
 */

// secp521r1 coordinate = 66 bytes, compressed point = 67 bytes
const COORD_SIZE = 66;
const POINT_SIZE = 67;

// Handshake
const HELLO = 0x01;          // Client -> Server: here is my DH public key
const WELCOME = 0x02;        // Server -> Client: here is your MO public key

// Sender-side Massey-Omura 3-pass
const MO_SEND_INIT = 0x10;   // Client sends C1 = mo.encrypt(E) + destination
const MO_SEND_STEP2 = 0x11;  // Server returns C2 = server_mo.encrypt(C1)
const MO_SEND_STEP3 = 0x12;  // Client sends C3 = mo.decrypt(C2)

// Receiver-side Massey-Omura 3-pass
const MO_RECV_INIT = 0x20;   // Server sends C1' = server_mo.encrypt(E) to receiver
const MO_RECV_STEP2 = 0x21;  // Receiver returns C2' = mo.encrypt(C1')
const MO_RECV_STEP3 = 0x22;  // Server sends C3' = server_mo.decrypt(C2') to receiver

// Control
const ERROR = 0x30;           // Error with 1-byte error code
const PEER_ONLINE = 0x31;     // A peer connected
const PEER_OFFLINE = 0x32;    // A peer disconnected
const MSG_ACK = 0x33;         // Server received the message (sender MO complete)
const MSG_DELIVERED = 0x34;   // Message delivered to recipient
const MSG_QUEUED = 0x35;      // Recipient offline, message queued

// Error codes
const ERR_USER_NOT_FOUND = 0x01;
const ERR_INVALID_FRAME = 0x02;
const ERR_SESSION_EXPIRED = 0x03;

/**
 * Convert a BigInt to a fixed-size big-endian Uint8Array.
 */
function bigintToBytes(value, length) {
    const bytes = new Uint8Array(length);
    let v = value;
    for (let i = length - 1; i >= 0; i--) {
        bytes[i] = Number(v & 0xFFn);
        v >>= 8n;
    }
    return bytes;
}

/**
 * Convert a Uint8Array (big-endian) to BigInt.
 */
function bytesToBigint(bytes, offset, length) {
    let result = 0n;
    for (let i = 0; i < length; i++) {
        result = (result << 8n) | BigInt(bytes[offset + i]);
    }
    return result;
}

function packPoint(x, parity) {
    const buf = new Uint8Array(POINT_SIZE);
    buf.set(bigintToBytes(x, COORD_SIZE), 0);
    buf[COORD_SIZE] = Number(parity);
    return buf;
}

function unpackPoint(data, offset = 0) {
    const x = bytesToBigint(data, offset, COORD_SIZE);
    const parity = BigInt(data[offset + COORD_SIZE]);
    return { x, parity, nextOffset: offset + POINT_SIZE };
}

function packFrame(msgType, payload) {
    const frame = new Uint8Array(3 + payload.length);
    frame[0] = msgType;
    frame[1] = (payload.length >> 8) & 0xFF;
    frame[2] = payload.length & 0xFF;
    frame.set(payload, 3);
    return frame;
}

function unpackFrame(data) {
    const arr = new Uint8Array(data);
    const msgType = arr[0];
    const payloadLen = (arr[1] << 8) | arr[2];
    const payload = arr.slice(3, 3 + payloadLen);
    return { msgType, payload };
}

// --- Pack functions ---

function packHello(pubkeyX, pubkeyParity) {
    return packFrame(HELLO, packPoint(pubkeyX, pubkeyParity));
}

function packMoSendInit(destX, destParity, j, c1X, c1Parity) {
    const dest = packPoint(destX, destParity);
    const c1 = packPoint(c1X, c1Parity);
    const payload = new Uint8Array(POINT_SIZE + 1 + POINT_SIZE);
    payload.set(dest, 0);
    payload[POINT_SIZE] = j;
    payload.set(c1, POINT_SIZE + 1);
    return packFrame(MO_SEND_INIT, payload);
}

function packMoSendStep3(sessionId, c3X, c3Parity) {
    const point = packPoint(c3X, c3Parity);
    const payload = new Uint8Array(4 + POINT_SIZE);
    const dv = new DataView(payload.buffer);
    dv.setUint32(0, sessionId);
    payload.set(point, 4);
    return packFrame(MO_SEND_STEP3, payload);
}

function packMoRecvStep2(sessionId, c2X, c2Parity) {
    const point = packPoint(c2X, c2Parity);
    const payload = new Uint8Array(4 + POINT_SIZE);
    const dv = new DataView(payload.buffer);
    dv.setUint32(0, sessionId);
    payload.set(point, 4);
    return packFrame(MO_RECV_STEP2, payload);
}

// --- Unpack functions ---

function unpackWelcome(payload) {
    return unpackPoint(payload);
}

function unpackMoSendStep2(payload) {
    const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    const sessionId = dv.getUint32(0);
    const { x, parity } = unpackPoint(payload, 4);
    return { sessionId, x, parity };
}

function unpackMoRecvInit(payload) {
    const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    const sessionId = dv.getUint32(0);
    let off = 4;
    const sender = unpackPoint(payload, off);
    off = sender.nextOffset;
    const j = payload[off];
    off += 1;
    const c1 = unpackPoint(payload, off);
    return {
        sessionId,
        senderX: sender.x,
        senderParity: sender.parity,
        j,
        c1X: c1.x,
        c1Parity: c1.parity,
    };
}

function unpackMoRecvStep3(payload) {
    const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    const sessionId = dv.getUint32(0);
    const { x, parity } = unpackPoint(payload, 4);
    return { sessionId, x, parity };
}

function unpackError(payload) {
    return payload[0];
}

function unpackPeerEvent(payload) {
    return unpackPoint(payload);
}

function unpackSessionId(payload) {
    const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    return dv.getUint32(0);
}

window.Protocol = {
    HELLO, WELCOME,
    MO_SEND_INIT, MO_SEND_STEP2, MO_SEND_STEP3,
    MO_RECV_INIT, MO_RECV_STEP2, MO_RECV_STEP3,
    ERROR, PEER_ONLINE, PEER_OFFLINE,
    MSG_ACK, MSG_DELIVERED, MSG_QUEUED,
    ERR_USER_NOT_FOUND, ERR_INVALID_FRAME, ERR_SESSION_EXPIRED,
    COORD_SIZE, POINT_SIZE,
    bigintToBytes, bytesToBigint,
    packPoint, unpackPoint,
    packFrame, unpackFrame,
    packHello, packMoSendInit, packMoSendStep3, packMoRecvStep2,
    unpackWelcome, unpackMoSendStep2, unpackMoRecvInit, unpackMoRecvStep3,
    unpackError, unpackPeerEvent, unpackSessionId,
};
