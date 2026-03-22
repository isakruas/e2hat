"""Session manager for Massey-Omura 3-pass protocol sessions.

Each message delivery requires a multi-step exchange (3-pass) between the server
and a client. A "session" tracks the state of one such exchange.

There are two kinds of sessions:
  1. Sender session: client sends an encrypted point to the server via 3-pass.
     States: WAIT_STEP3 -> (completed, session removed)
  2. Receiver session: server delivers an encrypted point to the receiver via 3-pass.
     States: WAIT_RECV_STEP2 -> (completed, session removed)

Session IDs are random 4-byte integers to prevent tracking across messages.

Each session stores metadata about the exchange (sender, destination, Koblitz
parameter j, the MO instance used) so the server can continue the protocol
when subsequent frames arrive.
"""

import os
import struct
import time

# Session states
WAIT_STEP3 = "WAIT_STEP3"            # Sender session: waiting for client's step 3
WAIT_RECV_STEP2 = "WAIT_RECV_STEP2"  # Receiver session: waiting for receiver's step 2


class SessionManager:
    """Async-safe manager for active Massey-Omura sessions.

    Sessions are short-lived: created when a 3-pass exchange starts and removed
    as soon as it completes. The random session ID is returned to the client so
    it can reference the correct session in subsequent frames.
    """

    def __init__(self):
        self._sessions = {}

    def _random_sid(self):
        """Generate a random 4-byte session ID, avoiding zero and collisions."""
        while True:
            sid = struct.unpack(">I", os.urandom(4))[0]
            if sid != 0 and sid not in self._sessions:
                return sid

    def create_session(self, **metadata):
        """Create a new session with random ID. Returns the session ID.

        Keyword arguments are stored as metadata (sender, dest, j, MO instances, etc.)
        """
        sid = self._random_sid()
        self._sessions[sid] = {
            "id": sid,
            "state": WAIT_STEP3,
            "metadata": metadata,
            "created_at": time.time(),
        }
        return sid

    def get(self, session_id):
        """Look up a session by ID. Returns None if not found."""
        return self._sessions.get(session_id)

    def set_state(self, session_id, state):
        """Transition a session to a new state."""
        session = self._sessions.get(session_id)
        if session:
            session["state"] = state

    def remove(self, session_id):
        """Remove a completed or expired session."""
        self._sessions.pop(session_id, None)

    def purge_stale(self, max_age=30):
        """Remove sessions older than max_age seconds."""
        now = time.time()
        stale = [
            sid for sid, sess in self._sessions.items()
            if now - sess.get("created_at", 0) > max_age
        ]
        for sid in stale:
            self._sessions.pop(sid, None)
        return len(stale)

    def cleanup_for_client(self, pubkey_hex):
        """Remove all sessions involving a disconnected client.

        Returns a list of dicts for WAIT_RECV_STEP2 sessions where the
        *receiver* (dest) disconnected and the message has stored e_x/e_parity.
        These can be re-enqueued for later delivery.
        """
        to_remove = []
        requeue = []
        for sid, sess in self._sessions.items():
            meta = sess["metadata"]
            if meta.get("sender") == pubkey_hex or meta.get("dest") == pubkey_hex:
                to_remove.append(sid)
                # Receiver disconnected mid-delivery
                if (
                    sess["state"] == WAIT_RECV_STEP2
                    and meta.get("dest") == pubkey_hex
                    and "e_x" in meta
                ):
                    requeue.append({
                        "sender": meta["sender"],
                        "dest": meta["dest"],
                        "j": meta["j"],
                        "e_x": meta["e_x"],
                        "e_parity": meta["e_parity"],
                        "send_sid": meta.get("send_sid"),
                        "queued_at": meta.get("queued_at"),
                        "sig_r": meta.get("sig_r"),
                        "sig_s": meta.get("sig_s"),
                        "timestamp_ms": meta.get("timestamp_ms"),
                    })
        for sid in to_remove:
            self._sessions.pop(sid, None)
        return requeue
