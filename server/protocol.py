"""Binary protocol for e2hat encrypted chat.

Every message exchanged over the WebSocket follows this frame format:

    [MSG_TYPE: 1 byte] [PAYLOAD_LEN: 2 bytes big-endian] [PAYLOAD: N bytes]

Elliptic curve points (secp521r1) are compressed to 67 bytes:

    [X coordinate: 66 bytes big-endian] [PARITY: 1 byte (0 or 1)]

Protocol phases:
    0x01-0x03  Handshake     HELLO → WELCOME (MO key + challenge) → AUTH (ECDSA sig)
    0x10-0x12  Send (MO)     Sender ↔ Server Massey-Omura 3-pass with signature relay
    0x20-0x22  Receive (MO)  Server ↔ Receiver Massey-Omura 3-pass with signature relay
    0x30-0x35  Control       Errors, presence, delivery status (ack/delivered/queued)
"""

import struct

# secp521r1 coordinate is 66 bytes (521 bits, rounded up to 66 bytes)
COORD_SIZE = 66
# Compressed point = X coordinate + 1 byte parity
POINT_SIZE = 67

# --- Message types ---
# Handshake: client sends HELLO with its DH public key, server replies WELCOME
# with a per-client Massey-Omura public key and a 32-byte challenge.
# Client responds with AUTH containing the signature of the challenge.
HELLO = 0x01
WELCOME = 0x02
AUTH = 0x03

# Sender-side Massey-Omura 3-pass:
#   SEND_INIT:  client sends encrypted point + destination
#   SEND_STEP2: server double-encrypts and returns to client
#   SEND_STEP3: client removes its layer, server can now decrypt to get E
MO_SEND_INIT = 0x10
MO_SEND_STEP2 = 0x11
MO_SEND_STEP3 = 0x12

# Receiver-side Massey-Omura 3-pass:
#   RECV_INIT:  server sends double-encrypted point to receiver
#   RECV_STEP2: receiver adds its layer and returns
#   RECV_STEP3: server removes its layer, receiver can now decrypt to get E
MO_RECV_INIT = 0x20
MO_RECV_STEP2 = 0x21
MO_RECV_STEP3 = 0x22

# Control messages
ERROR = 0x30         # Server reports an error condition
PEER_ONLINE = 0x31   # A peer connected to this server
PEER_OFFLINE = 0x32  # A peer disconnected from this server
MSG_ACK = 0x33       # Server received the message from sender (MO complete)
MSG_DELIVERED = 0x34  # Message was delivered to the recipient
MSG_QUEUED = 0x35    # Recipient is offline, message queued for later delivery


def pack_point(x, parity):
    """Pack a compressed point into 67 bytes."""
    return x.to_bytes(COORD_SIZE, "big") + struct.pack("B", parity)


def unpack_point(data, offset=0):
    """Unpack a compressed point from bytes. Returns (x, parity, new_offset)."""
    if len(data) < offset + POINT_SIZE:
        raise ValueError(f"Payload too short for point at offset {offset}: need {offset + POINT_SIZE}, got {len(data)}")
    x = int.from_bytes(data[offset:offset + COORD_SIZE], "big")
    parity = data[offset + COORD_SIZE]
    return x, parity, offset + POINT_SIZE


def pack_frame(msg_type, payload):
    """Pack a protocol frame."""
    return struct.pack("B", msg_type) + struct.pack(">H", len(payload)) + payload


def unpack_frame(data):
    """Unpack a protocol frame. Returns (msg_type, payload)."""
    if len(data) < 3:
        raise ValueError(f"Frame too short: need at least 3 bytes, got {len(data)}")
    msg_type = data[0]
    payload_len = struct.unpack(">H", data[1:3])[0]
    if len(data) < 3 + payload_len:
        raise ValueError(f"Frame truncated: header says {payload_len} bytes, got {len(data) - 3}")
    payload = data[3:3 + payload_len]
    return msg_type, payload


# --- Pack functions ---
# Each pack function builds a complete frame (header + payload) ready to send.

def pack_hello(client_pubkey_x, client_pubkey_parity):
    payload = pack_point(client_pubkey_x, client_pubkey_parity)
    return pack_frame(HELLO, payload)


def pack_welcome(server_mo_pubkey_x, server_mo_pubkey_parity, challenge):
    payload = pack_point(server_mo_pubkey_x, server_mo_pubkey_parity)
    payload += challenge  # 32 bytes
    return pack_frame(WELCOME, payload)


def unpack_welcome(payload):
    x, parity, off = unpack_point(payload)
    challenge = payload[off:off + 32]
    return x, parity, challenge


def pack_auth(r, s):
    """Pack ECDSA signature (r, s scalars)."""
    return pack_frame(AUTH, r.to_bytes(COORD_SIZE, "big") + s.to_bytes(COORD_SIZE, "big"))


def unpack_auth(payload):
    """Unpack ECDSA signature."""
    if len(payload) < COORD_SIZE * 2:
        raise ValueError(f"AUTH payload too short: need {COORD_SIZE * 2}, got {len(payload)}")
    r = int.from_bytes(payload[:COORD_SIZE], "big")
    s = int.from_bytes(payload[COORD_SIZE:COORD_SIZE*2], "big")
    return r, s


def pack_mo_send_init(dest_pubkey_x, dest_pubkey_parity, j, c1_x, c1_parity, sig_r=None, sig_s=None, timestamp_ms=None):
    payload = pack_point(dest_pubkey_x, dest_pubkey_parity)
    payload += struct.pack("B", j)
    payload += pack_point(c1_x, c1_parity)
    if sig_r is not None and sig_s is not None:
        payload += sig_r.to_bytes(COORD_SIZE, "big") + sig_s.to_bytes(COORD_SIZE, "big")
        payload += struct.pack(">Q", timestamp_ms or 0)
    return pack_frame(MO_SEND_INIT, payload)


def pack_mo_send_step2(session_id, c2_x, c2_parity):
    payload = struct.pack(">I", session_id) + pack_point(c2_x, c2_parity)
    return pack_frame(MO_SEND_STEP2, payload)


def pack_mo_send_step3(session_id, c3_x, c3_parity):
    payload = struct.pack(">I", session_id) + pack_point(c3_x, c3_parity)
    return pack_frame(MO_SEND_STEP3, payload)


def pack_mo_recv_init(
    session_id, sender_pubkey_x, sender_pubkey_parity, j,
    c1_x, c1_parity, sig_r=None, sig_s=None, timestamp_ms=None,
):
    payload = struct.pack(">I", session_id)
    payload += pack_point(sender_pubkey_x, sender_pubkey_parity)
    payload += struct.pack("B", j)
    payload += pack_point(c1_x, c1_parity)
    if sig_r is not None and sig_s is not None:
        payload += sig_r.to_bytes(COORD_SIZE, "big") + sig_s.to_bytes(COORD_SIZE, "big")
        payload += struct.pack(">Q", timestamp_ms or 0)
    return pack_frame(MO_RECV_INIT, payload)


def pack_mo_recv_step2(session_id, c2_x, c2_parity):
    payload = struct.pack(">I", session_id) + pack_point(c2_x, c2_parity)
    return pack_frame(MO_RECV_STEP2, payload)


def pack_mo_recv_step3(session_id, c3_x, c3_parity):
    payload = struct.pack(">I", session_id) + pack_point(c3_x, c3_parity)
    return pack_frame(MO_RECV_STEP3, payload)


def pack_error(error_code):
    return pack_frame(ERROR, struct.pack("B", error_code))


def pack_peer_online(peer_pubkey_x, peer_pubkey_parity):
    payload = pack_point(peer_pubkey_x, peer_pubkey_parity)
    return pack_frame(PEER_ONLINE, payload)


def pack_peer_offline(peer_pubkey_x, peer_pubkey_parity):
    payload = pack_point(peer_pubkey_x, peer_pubkey_parity)
    return pack_frame(PEER_OFFLINE, payload)


# --- Unpack functions ---
# Each unpack function receives a payload (without the frame header) and returns
# the parsed fields. The frame header is stripped by unpack_frame() first.

def unpack_hello(payload):
    x, parity, _ = unpack_point(payload)
    return x, parity


def unpack_mo_send_init(payload):
    dest_x, dest_parity, off = unpack_point(payload)
    if len(payload) < off + 1:
        raise ValueError("MO_SEND_INIT payload too short for j byte")
    j = payload[off]
    off += 1
    c1_x, c1_parity, off2 = unpack_point(payload, off)
    sig_r, sig_s, timestamp_ms = None, None, None
    if len(payload) >= off2 + COORD_SIZE * 2 + 8:
        sig_r = int.from_bytes(payload[off2:off2 + COORD_SIZE], "big")
        sig_s = int.from_bytes(payload[off2 + COORD_SIZE:off2 + COORD_SIZE * 2], "big")
        timestamp_ms = struct.unpack(">Q", payload[off2 + COORD_SIZE * 2:off2 + COORD_SIZE * 2 + 8])[0]
    return dest_x, dest_parity, j, c1_x, c1_parity, sig_r, sig_s, timestamp_ms


def unpack_mo_send_step3(payload):
    if len(payload) < 4:
        raise ValueError("MO_SEND_STEP3 payload too short for session ID")
    session_id = struct.unpack(">I", payload[:4])[0]
    c3_x, c3_parity, _ = unpack_point(payload, 4)
    return session_id, c3_x, c3_parity


def unpack_mo_recv_step2(payload):
    if len(payload) < 4:
        raise ValueError("MO_RECV_STEP2 payload too short for session ID")
    session_id = struct.unpack(">I", payload[:4])[0]
    c2_x, c2_parity, _ = unpack_point(payload, 4)
    return session_id, c2_x, c2_parity


def pack_msg_ack(session_id):
    return pack_frame(MSG_ACK, struct.pack(">I", session_id))


def pack_msg_delivered(session_id):
    return pack_frame(MSG_DELIVERED, struct.pack(">I", session_id))


def pack_msg_queued(session_id):
    return pack_frame(MSG_QUEUED, struct.pack(">I", session_id))


# Error codes sent inside ERROR frames
ERR_USER_NOT_FOUND = 0x01   # Destination public key not connected to this server
ERR_INVALID_FRAME = 0x02    # Malformed or unrecognized frame
ERR_SESSION_EXPIRED = 0x03  # Session ID not found or already completed
ERR_RATE_LIMITED = 0x04     # Too many messages, slow down
