"""e2hat relay server.

This server is a blind relay: it moves encrypted curve points between clients
using the Massey-Omura 3-pass protocol. It never has access to plaintext
messages or to the Diffie-Hellman shared secrets used for message encryption.

Architecture:
    - Single WebSocket endpoint at /ws
    - Each client is identified by its compressed DH public key (hex string)
    - On connect (HELLO), the server generates a random MO key pair for this client
    - Messages are relayed via two 3-pass exchanges:
        1. Sender -> Server: sender encrypts, server double-encrypts, sender strips
           its layer, server decrypts to obtain E (the DH-encrypted curve point)
        2. Server -> Receiver: server encrypts E, receiver double-encrypts, server
           strips its layer, receiver decrypts to obtain E
    - The receiver then uses DH to decrypt E back into the Koblitz-encoded message

State (stored in app dict):
    clients:  {pubkey_hex: {ws, mo}}     Active WebSocket connections
    sessions: SessionManager              Active Massey-Omura 3-pass exchanges
    queues:   {pubkey_hex: [messages]}    Messages for offline users
"""

import logging
import random

from aiohttp import web
from ecutils import MasseyOmura, Point, get_curve

from . import protocol as proto
from .session import WAIT_RECV_STEP2, WAIT_STEP3, SessionManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger(__name__)

CURVE_NAME = "secp521r1"
curve = get_curve(CURVE_NAME)


def _pubkey_hex(x, parity):
    """Canonical hex identifier for a compressed public key."""
    return f"{x:0132x}:{parity}"


def _random_mo_key():
    """Generate a random private key coprime with n for MO."""
    from math import gcd
    while True:
        k = random.randrange(2, curve.n)
        if gcd(k, curve.n) == 1:
            return k


async def websocket_handler(request):
    """Main WebSocket handler. Each connection goes through:
    1. Client sends HELLO with its DH public key
    2. Server replies WELCOME with a per-client MO public key
    3. Client can now send/receive messages via MO 3-pass frames
    """
    app = request.app
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    client_pubkey_hex = None

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.BINARY:
                try:
                    msg_type, payload = proto.unpack_frame(msg.data)
                except Exception:
                    await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))
                    continue

                if msg_type == proto.HELLO:
                    await _handle_hello(app, ws, payload)
                    x, parity = proto.unpack_hello(payload)
                    client_pubkey_hex = _pubkey_hex(x, parity)

                elif msg_type == proto.MO_SEND_INIT:
                    await _handle_mo_send_init(app, ws, payload, client_pubkey_hex)

                elif msg_type == proto.MO_SEND_STEP3:
                    await _handle_mo_send_step3(app, ws, payload)

                elif msg_type == proto.MO_RECV_STEP2:
                    await _handle_mo_recv_step2(app, ws, payload)

                else:
                    await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))

            elif msg.type == web.WSMsgType.ERROR:
                log.error("WS error: %s", ws.exception())
    finally:
        if client_pubkey_hex:
            _handle_disconnect(app, client_pubkey_hex)

    return ws


async def _handle_hello(app, ws, payload):
    x, parity = proto.unpack_hello(payload)
    pubkey_hex = _pubkey_hex(x, parity)

    # Generate a random MO instance for this client
    mo_key = _random_mo_key()
    mo = MasseyOmura(private_key=mo_key, curve_name=CURVE_NAME)

    app["clients"][pubkey_hex] = {"ws": ws, "mo": mo}
    log.info("Client connected: %s...", pubkey_hex[:20])

    # Send WELCOME with server's MO public key for this client
    # MO public key = mo_key * G
    from ecutils import DiffieHellman
    dh_temp = DiffieHellman(private_key=mo_key, curve_name=CURVE_NAME)
    server_mo_pub = dh_temp.public_key
    mo_pub_x, mo_pub_parity = server_mo_pub.compress()

    await ws.send_bytes(proto.pack_welcome(mo_pub_x, mo_pub_parity))

    # Notify other clients that this peer is online
    for other_hex, other_info in app["clients"].items():
        if other_hex != pubkey_hex:
            try:
                await other_info["ws"].send_bytes(
                    proto.pack_peer_online(x, parity)
                )
                # Also tell the new client about existing peers
                ox, op = _parse_pubkey_hex(other_hex)
                await ws.send_bytes(proto.pack_peer_online(ox, op))
            except Exception:  # noqa: S110
                pass  # Best-effort notification, ignore if peer WS is closing

    # Deliver queued messages
    await _deliver_queued(app, pubkey_hex)


async def _handle_mo_send_init(app, ws, payload, sender_hex):
    """Sender MO step 1: client sends C1 = client_mo.encrypt(E).
    Server computes C2 = server_mo.encrypt(C1) and returns it.
    """
    dest_x, dest_parity, j, c1_x, c1_parity = proto.unpack_mo_send_init(payload)
    dest_hex = _pubkey_hex(dest_x, dest_parity)

    # Get server's MO for the sender
    sender_info = app["clients"].get(sender_hex)
    if not sender_info:
        await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))
        return

    server_mo = sender_info["mo"]

    # Reconstruct C1 as a point
    c1_point = Point.decompress(c1_x, c1_parity, curve)

    # Server encrypts C1 -> C2
    c2_point = server_mo.encrypt(c1_point)
    c2_x, c2_parity = c2_point.compress()

    # Create session
    sessions = app["sessions"]
    sid = sessions.create_session(
        sender=sender_hex,
        dest=dest_hex,
        j=j,
        server_mo_sender=server_mo,
    )

    # Send step 2 back to sender
    await ws.send_bytes(proto.pack_mo_send_step2(sid, c2_x, c2_parity))


async def _handle_mo_send_step3(app, ws, payload):
    """Sender MO step 3: client sends C3 = client_mo.decrypt(C2).
    Server computes E = server_mo.decrypt(C3) to recover the DH-encrypted point.
    Then initiates delivery to the receiver.
    """
    session_id, c3_x, c3_parity = proto.unpack_mo_send_step3(payload)

    sessions = app["sessions"]
    session = sessions.get(session_id)
    if not session or session["state"] != WAIT_STEP3:
        await ws.send_bytes(proto.pack_error(proto.ERR_SESSION_EXPIRED))
        return

    # C3 = sender.decrypt(C2) -> server decrypts to get E
    server_mo = session["metadata"]["server_mo_sender"]
    c3_point = Point.decompress(c3_x, c3_parity, curve)
    e_point = server_mo.decrypt(c3_point)

    # Store E and metadata for delivery
    dest_hex = session["metadata"]["dest"]
    sender_hex = session["metadata"]["sender"]
    j = session["metadata"]["j"]

    # Clean up sender session
    sessions.remove(session_id)

    # ACK: server received and decrypted the message
    await ws.send_bytes(proto.pack_msg_ack(session_id))

    # Now deliver to receiver, passing send_session_id for status tracking
    await _initiate_delivery(app, sender_hex, dest_hex, j, e_point, session_id)


async def _initiate_delivery(app, sender_hex, dest_hex, j, e_point, send_sid=None):
    """Start MO 3-pass delivery to receiver."""
    dest_info = app["clients"].get(dest_hex)

    if not dest_info:
        # Queue for offline delivery
        queue = app["queues"].setdefault(dest_hex, [])
        e_x, e_parity = e_point.compress()
        queue.append({
            "sender": sender_hex,
            "j": j,
            "e_x": e_x,
            "e_parity": e_parity,
            "send_sid": send_sid,
        })
        log.info("Queued message for offline user %s...", dest_hex[:20])
        # Notify sender: queued
        if send_sid is not None:
            sender_info = app["clients"].get(sender_hex)
            if sender_info:
                await sender_info["ws"].send_bytes(proto.pack_msg_queued(send_sid))
        return

    # Get server's MO for the receiver
    server_mo = dest_info["mo"]

    # Server encrypts E -> C1'
    c1_point = server_mo.encrypt(e_point)
    c1_x, c1_parity = c1_point.compress()

    # Create delivery session
    sessions = app["sessions"]
    sid = sessions.create_session(
        sender=sender_hex,
        dest=dest_hex,
        j=j,
        server_mo_receiver=server_mo,
        send_sid=send_sid,
    )
    sessions.set_state(sid, WAIT_RECV_STEP2)

    # Parse sender pubkey for the frame
    sender_x, sender_parity = _parse_pubkey_hex(sender_hex)

    # Send MO_RECV_INIT to receiver
    await dest_info["ws"].send_bytes(
        proto.pack_mo_recv_init(sid, sender_x, sender_parity, j, c1_x, c1_parity)
    )


async def _handle_mo_recv_step2(app, ws, payload):
    """Receiver MO step 2: receiver sends C2' = receiver_mo.encrypt(C1').
    Server computes C3' = server_mo.decrypt(C2') and sends it to receiver.
    Receiver can then decrypt: E = receiver_mo.decrypt(C3').
    """
    session_id, c2_x, c2_parity = proto.unpack_mo_recv_step2(payload)

    sessions = app["sessions"]
    session = sessions.get(session_id)
    if not session or session["state"] != WAIT_RECV_STEP2:
        await ws.send_bytes(proto.pack_error(proto.ERR_SESSION_EXPIRED))
        return

    # C2' = receiver.encrypt(C1') -> server decrypts to get C3'
    server_mo = session["metadata"]["server_mo_receiver"]
    c2_point = Point.decompress(c2_x, c2_parity, curve)
    c3_point = server_mo.decrypt(c2_point)
    c3_x, c3_parity = c3_point.compress()

    dest_hex = session["metadata"]["dest"]
    sender_hex = session["metadata"]["sender"]
    send_sid = session["metadata"].get("send_sid")
    dest_info = app["clients"].get(dest_hex)

    # Clean up session
    sessions.remove(session_id)

    if dest_info:
        await dest_info["ws"].send_bytes(
            proto.pack_mo_recv_step3(session_id, c3_x, c3_parity)
        )

    # Notify sender: delivered to recipient
    if send_sid is not None:
        sender_info = app["clients"].get(sender_hex)
        if sender_info:
            await sender_info["ws"].send_bytes(proto.pack_msg_delivered(send_sid))


async def _deliver_queued(app, pubkey_hex):
    """Deliver queued messages to a client that just connected."""
    queue = app["queues"].pop(pubkey_hex, [])
    for item in queue:
        e_point = Point.decompress(item["e_x"], item["e_parity"], curve)
        await _initiate_delivery(
            app, item["sender"], pubkey_hex, item["j"], e_point,
            item.get("send_sid"),
        )


def _handle_disconnect(app, pubkey_hex):
    """Clean up when a client disconnects."""
    app["clients"].pop(pubkey_hex, None)
    app["sessions"].cleanup_for_client(pubkey_hex)

    x, parity = _parse_pubkey_hex(pubkey_hex)
    # Notify others (best-effort, ignore failures on closing sockets)
    import asyncio
    for _other_hex, other_info in app["clients"].items():
        try:
            asyncio.ensure_future(
                other_info["ws"].send_bytes(proto.pack_peer_offline(x, parity))
            )
        except Exception:  # noqa: S110
            pass

    log.info("Client disconnected: %s...", pubkey_hex[:20])


def _parse_pubkey_hex(pubkey_hex):
    """Parse 'hex_x:parity' back into (x_int, parity_int)."""
    parts = pubkey_hex.split(":")
    return int(parts[0], 16), int(parts[1])


def create_app():
    app = web.Application()
    app["clients"] = {}
    app["sessions"] = SessionManager()
    app["queues"] = {}

    app.router.add_get("/ws", websocket_handler)

    return app


if __name__ == "__main__":
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=8080)  # noqa: S104
