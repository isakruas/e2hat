"""e2hat relay server.

This server is a blind relay: it moves encrypted curve points between clients
using the Massey-Omura 3-pass protocol. It never has access to plaintext
messages or to the Diffie-Hellman shared secrets used for message encryption.
"""

import asyncio
import logging
import os
import secrets
import time

from aiohttp import web
from ecutils import DiffieHellman, MasseyOmura, Point, get_curve

from . import protocol as proto
from .session import WAIT_RECV_STEP2, WAIT_STEP3, SessionManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger(__name__)

CURVE_NAME = "secp521r1"
curve = get_curve(CURVE_NAME)
QUEUE_TTL = 86400  # 24 hours in seconds
MAX_QUEUE_PER_USER = 100  # Max queued messages per offline user
MAX_DESTS_PER_SENDER = 500  # Max distinct offline destinations per sender
RATE_LIMIT_WINDOW = 10  # seconds
RATE_LIMIT_MAX = 200  # max messages per window per connection


_rate_limits = {}  # pubkey_hex -> list of timestamps


def _check_rate_limit(pubkey_hex):
    """Return True if the connection is within rate limits, False if exceeded."""
    if not pubkey_hex:
        return False
    now = time.time()
    timestamps = _rate_limits.setdefault(pubkey_hex, [])
    # Prune old entries
    cutoff = now - RATE_LIMIT_WINDOW
    _rate_limits[pubkey_hex] = timestamps = [t for t in timestamps if t > cutoff]
    if len(timestamps) >= RATE_LIMIT_MAX:
        return False
    timestamps.append(now)
    return True


def _pubkey_hex(x, parity):
    """Canonical hex identifier for a compressed public key."""
    return f"{x:0132x}:{parity}"


def _random_mo_key():
    """Generate a random private key coprime with n for MO using secrets."""
    from math import gcd
    while True:
        k = secrets.randbelow(curve.n - 2) + 2
        if gcd(k, curve.n) == 1:
            return k


async def websocket_handler(request):
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

                try:
                    if msg_type == proto.HELLO:
                        await _handle_hello(app, ws, payload)

                    elif msg_type == proto.AUTH:
                        client_pubkey_hex = await _handle_auth(app, ws, payload)

                    elif msg_type == proto.MO_SEND_INIT:
                        if not _check_rate_limit(client_pubkey_hex):
                            await ws.send_bytes(proto.pack_error(proto.ERR_RATE_LIMITED))
                            continue
                        await _handle_mo_send_init(app, ws, payload, client_pubkey_hex)

                    elif msg_type == proto.MO_SEND_STEP3:
                        await _handle_mo_send_step3(app, ws, payload, client_pubkey_hex)

                    elif msg_type == proto.MO_RECV_STEP2:
                        await _handle_mo_recv_step2(app, ws, payload, client_pubkey_hex)

                    else:
                        await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))
                except Exception as exc:
                    log.exception("Handler error (msg_type=%s): %s", msg_type, exc)
                    await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))

            elif msg.type == web.WSMsgType.ERROR:
                log.error("WS error: %s", ws.exception())
    finally:
        if client_pubkey_hex:
            await _handle_disconnect(app, client_pubkey_hex)

    return ws


async def _handle_hello(app, ws, payload):
    x, parity = proto.unpack_hello(payload)
    pubkey_hex = _pubkey_hex(x, parity)

    # Temporary storage for challenge verification
    challenge = os.urandom(32)

    # Store temporary state on the WS object itself (not fully active yet)
    ws["handshake"] = {
        "pubkey_x": x,
        "pubkey_parity": parity,
        "pubkey_hex": pubkey_hex,
        "challenge": challenge
    }

    # Generate a random MO instance for this client
    mo_key = _random_mo_key()
    mo = MasseyOmura(private_key=mo_key, curve_name=CURVE_NAME)
    ws["mo"] = mo

    # Derive MO public key (mo_key * G) and send in WELCOME with challenge
    server_mo_pub = DiffieHellman(private_key=mo_key, curve_name=CURVE_NAME).public_key
    mo_pub_x, mo_pub_parity = server_mo_pub.compress()

    await ws.send_bytes(proto.pack_welcome(mo_pub_x, mo_pub_parity, challenge))


async def _handle_auth(app, ws, payload):
    """Verify ECDSA signature of the challenge."""
    h = ws.get("handshake")
    if not h:
        await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))
        return None

    try:
        from ecutils import DigitalSignature
        r, s = proto.unpack_auth(payload)

        # Domain-separated verification: AUTH:<challenge_hex>
        challenge_hex = h["challenge"].hex()
        auth_payload = f"AUTH:{challenge_hex}".encode()

        pubkey = Point.decompress(h["pubkey_x"], h["pubkey_parity"], curve)

        # verify_message hashes the payload internally
        signer = DigitalSignature(1, CURVE_NAME)
        if not signer.verify_message(pubkey, auth_payload, r, s):
            raise ValueError("Invalid ECDSA signature")

    except Exception as e:
        log.warning("Auth failed for %s: %s", h["pubkey_hex"][:20], e)
        await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))
        await ws.close()
        return None

    pubkey_hex = h["pubkey_hex"]
    app["clients"][pubkey_hex] = {"ws": ws, "mo": ws["mo"]}
    log.info("Client authenticated: %s...", pubkey_hex[:20])

    # Notify other clients that this peer is online (only authenticated ones)
    for other_hex, other_info in app["clients"].items():
        if other_hex != pubkey_hex:
            try:
                await other_info["ws"].send_bytes(
                    proto.pack_peer_online(h["pubkey_x"], h["pubkey_parity"])
                )
                ox, op = _parse_pubkey_hex(other_hex)
                await ws.send_bytes(proto.pack_peer_online(ox, op))
            except Exception:  # noqa: S110
                pass

    # Deliver queued messages
    await _deliver_queued(app, pubkey_hex)
    return pubkey_hex


async def _handle_mo_send_init(app, ws, payload, sender_hex):
    if not sender_hex:
        await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))
        return

    dest_x, dest_parity, j, c1_x, c1_parity, sig_r, sig_s, timestamp_ms = proto.unpack_mo_send_init(payload)
    dest_hex = _pubkey_hex(dest_x, dest_parity)

    sender_info = app["clients"].get(sender_hex)
    if not sender_info:
        await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))
        return

    server_mo = sender_info["mo"]
    c1_point = Point.decompress(c1_x, c1_parity, curve)
    c2_point = server_mo.encrypt(c1_point)
    c2_x, c2_parity = c2_point.compress()

    sid = app["sessions"].create_session(
        sender=sender_hex,
        dest=dest_hex,
        j=j,
        server_mo_sender=server_mo,
        sig_r=sig_r,
        sig_s=sig_s,
        timestamp_ms=timestamp_ms,
    )
    await ws.send_bytes(proto.pack_mo_send_step2(sid, c2_x, c2_parity))


async def _handle_mo_send_step3(app, ws, payload, client_pubkey_hex):
    if not client_pubkey_hex:
        await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))
        return
    session_id, c3_x, c3_parity = proto.unpack_mo_send_step3(payload)
    sessions = app["sessions"]
    session = sessions.get(session_id)
    if not session or session["state"] != WAIT_STEP3:
        await ws.send_bytes(proto.pack_error(proto.ERR_SESSION_EXPIRED))
        return
    if session["metadata"]["sender"] != client_pubkey_hex:
        await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))
        return

    server_mo = session["metadata"]["server_mo_sender"]
    c3_point = Point.decompress(c3_x, c3_parity, curve)
    e_point = server_mo.decrypt(c3_point)

    dest_hex = session["metadata"]["dest"]
    sender_hex = session["metadata"]["sender"]
    j = session["metadata"]["j"]
    sig_r = session["metadata"].get("sig_r")
    sig_s = session["metadata"].get("sig_s")
    timestamp_ms = session["metadata"].get("timestamp_ms")
    sessions.remove(session_id)
    await ws.send_bytes(proto.pack_msg_ack(session_id))
    await _initiate_delivery(
        app, sender_hex, dest_hex, j, e_point, session_id,
        sig_r=sig_r, sig_s=sig_s, timestamp_ms=timestamp_ms,
    )


async def _initiate_delivery(
    app, sender_hex, dest_hex, j, e_point,
    send_sid=None, queued_at=None, sig_r=None, sig_s=None, timestamp_ms=None,
):
    dest_info = app["clients"].get(dest_hex)

    if not dest_info:
        # Per-sender limit: prevent one sender from creating queues to unlimited destinations
        sender_dests = app["queue_owners"].setdefault(sender_hex, set())
        if dest_hex not in app["queues"] and dest_hex not in sender_dests:
            if len(sender_dests) >= MAX_DESTS_PER_SENDER:
                log.warning("Sender %s... hit dest queue limit, dropping", sender_hex[:20])
                return
        queue = app["queues"].setdefault(dest_hex, [])
        if len(queue) >= MAX_QUEUE_PER_USER:
            queue.pop(0)  # Drop oldest to make room
        e_x, e_parity = e_point.compress()
        queue.append({
            "sender": sender_hex, "j": j, "e_x": e_x, "e_parity": e_parity,
            "send_sid": send_sid, "queued_at": queued_at or time.time(),
            "sig_r": sig_r, "sig_s": sig_s, "timestamp_ms": timestamp_ms,
        })
        sender_dests.add(dest_hex)
        if send_sid is not None:
            sender_info = app["clients"].get(sender_hex)
            if sender_info:
                await sender_info["ws"].send_bytes(proto.pack_msg_queued(send_sid))
        return

    server_mo = dest_info["mo"]
    c1_point = server_mo.encrypt(e_point)
    c1_x, c1_parity = c1_point.compress()

    e_x, e_parity = e_point.compress()
    sid = app["sessions"].create_session(
        sender=sender_hex, dest=dest_hex, j=j,
        server_mo_receiver=server_mo, send_sid=send_sid,
        e_x=e_x, e_parity=e_parity, queued_at=queued_at or time.time(),
        sig_r=sig_r, sig_s=sig_s, timestamp_ms=timestamp_ms,
    )
    app["sessions"].set_state(sid, WAIT_RECV_STEP2)
    sender_x, sender_parity = _parse_pubkey_hex(sender_hex)
    await dest_info["ws"].send_bytes(
        proto.pack_mo_recv_init(sid, sender_x, sender_parity, j, c1_x, c1_parity, sig_r, sig_s, timestamp_ms)
    )


async def _handle_mo_recv_step2(app, ws, payload, client_pubkey_hex):
    if not client_pubkey_hex:
        await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))
        return
    session_id, c2_x, c2_parity = proto.unpack_mo_recv_step2(payload)
    sessions = app["sessions"]
    session = sessions.get(session_id)
    if not session or session["state"] != WAIT_RECV_STEP2:
        await ws.send_bytes(proto.pack_error(proto.ERR_SESSION_EXPIRED))
        return
    if session["metadata"]["dest"] != client_pubkey_hex:
        await ws.send_bytes(proto.pack_error(proto.ERR_INVALID_FRAME))
        return

    server_mo = session["metadata"]["server_mo_receiver"]
    c2_point = Point.decompress(c2_x, c2_parity, curve)
    c3_point = server_mo.decrypt(c2_point)
    c3_x, c3_parity = c3_point.compress()

    dest_hex = session["metadata"]["dest"]
    sender_hex = session["metadata"]["sender"]
    send_sid = session["metadata"].get("send_sid")
    dest_info = app["clients"].get(dest_hex)
    sessions.remove(session_id)

    if dest_info:
        await dest_info["ws"].send_bytes(proto.pack_mo_recv_step3(session_id, c3_x, c3_parity))

    if send_sid is not None:
        sender_info = app["clients"].get(sender_hex)
        if sender_info:
            await sender_info["ws"].send_bytes(proto.pack_msg_delivered(send_sid))


async def _deliver_queued(app, pubkey_hex):
    now = time.time()
    queue = app["queues"].pop(pubkey_hex, [])
    # Clean up queue_owners references to this dest
    for sender_hex, dests in app["queue_owners"].items():
        dests.discard(pubkey_hex)
    for item in queue:
        queued_at = item.get("queued_at", now)
        if now - queued_at > QUEUE_TTL:
            continue
        e_point = Point.decompress(item["e_x"], item["e_parity"], curve)
        await _initiate_delivery(
            app, item["sender"], pubkey_hex, item["j"], e_point,
            item.get("send_sid"), queued_at,
            sig_r=item.get("sig_r"), sig_s=item.get("sig_s"),
            timestamp_ms=item.get("timestamp_ms"),
        )


async def _handle_disconnect(app, pubkey_hex):
    app["clients"].pop(pubkey_hex, None)
    requeue_items = app["sessions"].cleanup_for_client(pubkey_hex)
    for item in requeue_items:
        app["queues"].setdefault(item["dest"], []).append(item)

    x, parity = _parse_pubkey_hex(pubkey_hex)
    notify = []
    for _other_hex, other_info in app["clients"].items():
        notify.append(other_info["ws"].send_bytes(proto.pack_peer_offline(x, parity)))
    if notify:
        await asyncio.gather(*notify, return_exceptions=True)
    log.info("Client disconnected: %s...", pubkey_hex[:20])


def _parse_pubkey_hex(pubkey_hex):
    parts = pubkey_hex.split(":")
    return int(parts[0], 16), int(parts[1])


async def _purge_stale_sessions(app):
    """Periodically purge stale MO sessions and expired rate limit entries."""
    while True:
        await asyncio.sleep(30)
        purged = app["sessions"].purge_stale(max_age=120)
        if purged:
            log.info("Purged %d stale session(s)", purged)
        # Purge expired rate limit entries
        cutoff = time.time() - RATE_LIMIT_WINDOW
        stale_keys = [k for k, ts in _rate_limits.items() if not ts or ts[-1] < cutoff]
        for k in stale_keys:
            del _rate_limits[k]


async def _on_startup(app):
    app["_purge_task"] = asyncio.create_task(_purge_stale_sessions(app))


async def _on_cleanup(app):
    task = app.get("_purge_task")
    if task:
        task.cancel()


def create_app():
    app = web.Application()
    app["clients"] = {}
    app["sessions"] = SessionManager()
    app["queues"] = {}
    app["queue_owners"] = {}  # sender_hex -> set of dest_hexes they queued to
    app.router.add_get("/ws", websocket_handler)
    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)
    return app


if __name__ == "__main__":
    app = create_app()
    web.run_app(app, host="0.0.0.0", port=8080)  # noqa: S104
