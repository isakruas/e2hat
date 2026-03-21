/**
 * e2hat - End-to-end encrypted chat with elliptic curves.
 *
 * Cryptographic flow for sending a message:
 *   1. Koblitz.encode(text) -> (M, j)          Text becomes a curve point
 *   2. E = M * shared.x                        DH encryption (shared = DH with recipient)
 *   3. C1 = mo.encrypt(E)                      MO layer for transit to server
 *   4. Server 3-pass (SEND_INIT/STEP2/STEP3)   Server receives E without seeing M
 *   5. Server 3-pass (RECV_INIT/STEP2/STEP3)   Receiver gets E
 *   6. M = E * modInverse(shared.x, n)          DH decryption
 *   7. Koblitz.decode(M, j) -> text             Curve point becomes text
 *
 * The server only ever sees E (encrypted with DH). It cannot derive the DH
 * shared secret because it doesn't have either party's private key.
 *
 * Multi-server: the frontend connects to multiple relay servers simultaneously.
 * Each server has its own MO key pair and WebSocket connection.
 */

const { createApp, ref, reactive, computed, nextTick, watch } = Vue;
const { Point, DiffieHellman, MasseyOmura, Koblitz, getCurve } = ecutils;

const CURVE_NAME = 'secp521r1';
const curve = getCurve(CURVE_NAME);
const P = Protocol;

// --- Cryptographic utilities ---

/** Generate a random private key in range [2, n-1] for secp521r1. */
function randomPrivateKey() {
    const bytes = new Uint8Array(66);
    crypto.getRandomValues(bytes);
    let k = 0n;
    for (const b of bytes) k = (k << 8n) | BigInt(b);
    return (k % (curve.n - 2n)) + 2n;
}

function gcd(a, b) {
    a = a < 0n ? -a : a;
    b = b < 0n ? -b : b;
    while (b > 0n) { [a, b] = [b, a % b]; }
    return a;
}

/** Generate a random key coprime with curve order n (required for Massey-Omura). */
function randomMoKey() {
    while (true) {
        const k = randomPrivateKey();
        if (gcd(k, curve.n) === 1n) return k;
    }
}

/** Serialize a compressed point as "hex_x:parity" string (used as identifier). */
function pointToHex(x, parity) {
    return x.toString(16).padStart(132, '0') + ':' + parity.toString();
}

/** Deserialize "hex_x:parity" string back to {x, parity} BigInts. */
function hexToPoint(hex) {
    const parts = hex.split(':');
    return { x: BigInt('0x' + parts[0]), parity: BigInt(parts[1]) };
}

/** Extended Euclidean algorithm for modular inverse (needed for DH decryption). */
function modInverse(a, m) {
    a = ((a % m) + m) % m;
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }
    return ((old_s % m) + m) % m;
}

// --- Password-based key management ---
// Keys are encrypted using Koblitz: encode the password as a curve point,
// use its X coordinate as a derived key, then add/subtract mod n to encrypt/decrypt.

/** Derive a deterministic key from a password using Koblitz encoding. */
function deriveKeyFromPassword(password) {
    const kob = new Koblitz(CURVE_NAME);
    const [point] = kob.encode(password);
    return point.x;
}

/** Encrypt a private key: (key + derived) mod n. */
function encryptKey(privateKey, derivedKey) {
    return ((privateKey + derivedKey) % curve.n).toString(16);
}

/** Decrypt a private key: (encrypted - derived) mod n. */
function decryptKey(encryptedHex, derivedKey) {
    const encrypted = BigInt('0x' + encryptedHex);
    return ((encrypted - derivedKey) % curve.n + curve.n) % curve.n;
}

// --- localStorage message encryption ---
// Messages are XOR-encrypted with the derived key bytes before storing.
// This prevents reading message history without the password.

function xorEncrypt(text, derivedKey) {
    const keyBytes = [];
    let k = derivedKey;
    for (let i = 0; i < 66; i++) { keyBytes.push(Number(k & 0xFFn)); k >>= 8n; }
    const textBytes = new TextEncoder().encode(text);
    const out = new Uint8Array(textBytes.length);
    for (let i = 0; i < textBytes.length; i++) out[i] = textBytes[i] ^ keyBytes[i % keyBytes.length];
    return Array.from(out, b => b.toString(16).padStart(2, '0')).join('');
}

function xorDecrypt(hex, derivedKey) {
    const keyBytes = [];
    let k = derivedKey;
    for (let i = 0; i < 66; i++) { keyBytes.push(Number(k & 0xFFn)); k >>= 8n; }
    const encBytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < encBytes.length; i++) encBytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    const out = new Uint8Array(encBytes.length);
    for (let i = 0; i < encBytes.length; i++) out[i] = encBytes[i] ^ keyBytes[i % keyBytes.length];
    return new TextDecoder().decode(out);
}

createApp({
    setup() {
        const screen = ref('setup');
        const view = ref('contacts');
        const showServers = ref(true);
        const nickname = ref(localStorage.getItem('e2hat_nickname') || '');
        const status = ref('');
        const logs = ref([]);

        const dhPrivateKey = ref(null);
        const dhPublicKey = ref(null);
        const moInstance = ref(null);
        const moPrivateKey = ref(null);
        const myPubKeyHex = ref('');
        let derivedKeyCache = null;

        // --- Multi-server state ---
        // Each server entry holds its own WebSocket, MO instance, and peer tracking.
        // Servers are independent relays — a message is routed through whichever
        // server the recipient is connected to.
        const DEFAULT_SERVERS = [
            { name: 'Mango', url: 'ws://0.0.0.0:8080/ws' },
            { name: 'Papaya', url: 'ws://0.0.0.0:8081/ws' },
            { name: 'Guava', url: 'ws://0.0.0.0:8082/ws' },
        ];
        const savedServers = JSON.parse(localStorage.getItem('e2hat_servers') || 'null');
        const initialServers = savedServers !== null ? savedServers : DEFAULT_SERVERS;
        const servers = reactive(initialServers.map(s => ({
            name: s.name,
            url: s.url,
            state: 'disconnected',
            ws: null,
            mo: null,
            onlinePeers: new Set(),
        })));

        const contacts = reactive(JSON.parse(localStorage.getItem('e2hat_contacts') || '[]'));
        const activeContact = ref(null);
        const messages = reactive({});
        const messageInput = ref('');
        const unreadMessages = reactive({});
        const editingContact = ref(null);

        const newContactNick = ref('');
        const newContactKey = ref('');
        const newServerName = ref('');
        const newServerUrl = ref('');
        const showAddContact = ref(false);
        const showAddServer = ref(false);

        // Pending MO 3-pass sessions, keyed by session ID.
        // Send sessions track outgoing messages mid-3-pass (we need the MO instance to decrypt step 2).
        // Recv sessions track incoming messages mid-3-pass (we need the MO instance to decrypt step 3).
        // A temporary key '_next_send_<srvIdx>' holds the session before the server assigns an ID.
        const pendingSendSessions = reactive({});
        const pendingRecvSessions = reactive({});
        // Maps MO session IDs to {destHex, msgIndex} so we can update delivery status
        // (sending -> sent -> delivered/queued) on the correct message in the UI.
        const sentMessageMap = reactive({});

        const koblitz = new Koblitz(CURVE_NAME);
        const messagesEl = ref(null);
        const logEl = ref(null);
        const logHeight = ref(80);
        const copied = ref(false);
        let copiedTimeout = null;

        const hasSavedKeys = ref(!!localStorage.getItem('e2hat_encrypted_keys'));
        const restoredKeys = ref(false);
        const restorePassword = ref('');
        const savePassword = ref('');
        const keysSaved = ref(false);

        // --- Computed ---
        const activeMessages = computed(() => {
            if (!activeContact.value) return [];
            return messages[activeContact.value.keyHex] || [];
        });

        const compressedPubKeyDisplay = computed(() => {
            if (!dhPublicKey.value) return '';
            const [x, parity] = dhPublicKey.value.compress();
            return pointToHex(x, parity);
        });

        // --- Helpers ---
        function isOnline(keyHex) {
            return servers.some(s => s.state === 'connected' && s.onlinePeers.has(keyHex));
        }

        function findServerForPeer(keyHex) {
            for (let i = 0; i < servers.length; i++) {
                if (servers[i].state === 'connected' && servers[i].onlinePeers.has(keyHex)) return i;
            }
            // Fallback: first connected server (message will be queued server-side)
            for (let i = 0; i < servers.length; i++) {
                if (servers[i].state === 'connected') return i;
            }
            return -1;
        }

        function unreadCount(keyHex) { return unreadMessages[keyHex] || 0; }

        // --- Log ---
        function log(msg) {
            const ts = new Date().toLocaleTimeString();
            logs.value.push(`[${ts}] ${msg}`);
            if (logs.value.length > 200) logs.value.splice(0, 50);
            nextTick(() => { if (logEl.value) logEl.value.scrollTop = logEl.value.scrollHeight; });
        }

        // --- Log resize ---
        function startLogResize(e) {
            const startY = e.type === 'touchstart' ? e.touches[0].clientY : e.clientY;
            const startH = logHeight.value;
            function onMove(ev) {
                const y = ev.type === 'touchmove' ? ev.touches[0].clientY : ev.clientY;
                logHeight.value = Math.max(40, Math.min(400, startH + (startY - y)));
            }
            function onEnd() {
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onEnd);
                document.removeEventListener('touchmove', onMove);
                document.removeEventListener('touchend', onEnd);
            }
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onEnd);
            document.addEventListener('touchmove', onMove, { passive: true });
            document.addEventListener('touchend', onEnd);
        }

        // --- Clipboard ---
        function copyToClipboard(text) {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            try { document.execCommand('copy'); } catch {}
            document.body.removeChild(ta);
        }

        function copyPubKey() {
            if (!compressedPubKeyDisplay.value) return;
            const text = compressedPubKeyDisplay.value;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).catch(() => copyToClipboard(text));
            } else {
                copyToClipboard(text);
            }
            copied.value = true;
            clearTimeout(copiedTimeout);
            copiedTimeout = setTimeout(() => { copied.value = false; }, 1500);
        }

        // --- Encrypted persistence ---
        function saveMessages() {
            if (!derivedKeyCache) return;
            const plain = JSON.stringify(messages);
            localStorage.setItem('e2hat_encrypted_messages', xorEncrypt(plain, derivedKeyCache));
        }

        function loadMessages(dk) {
            const enc = localStorage.getItem('e2hat_encrypted_messages');
            if (!enc) return;
            try {
                const parsed = JSON.parse(xorDecrypt(enc, dk));
                for (const key of Object.keys(parsed)) messages[key] = parsed[key];
                log(`Messages restored (${Object.keys(parsed).length} conversations)`);
            } catch { log('Could not restore messages'); }
        }

        function saveServers() {
            localStorage.setItem('e2hat_servers', JSON.stringify(servers.map(s => ({ name: s.name, url: s.url }))));
        }

        function saveContacts() {
            localStorage.setItem('e2hat_contacts', JSON.stringify(contacts));
        }

        // --- Key management ---
        function generateKeys() {
            status.value = 'Generating keys...';
            setTimeout(() => {
                dhPrivateKey.value = randomPrivateKey();
                const dh = new DiffieHellman(dhPrivateKey.value, CURVE_NAME);
                dhPublicKey.value = dh.publicKey;
                const moKey = randomMoKey();
                moPrivateKey.value = moKey;
                moInstance.value = new MasseyOmura(moKey, CURVE_NAME);
                const [x, parity] = dhPublicKey.value.compress();
                myPubKeyHex.value = pointToHex(x, parity);
                status.value = 'Keys generated!';
                log('DH and MO key pairs generated');
            }, 50);
        }

        function saveKeys() {
            if (!savePassword.value.trim() || !dhPrivateKey.value || !moPrivateKey.value) return;
            status.value = 'Encrypting keys...';
            setTimeout(() => {
                try {
                    const dk = deriveKeyFromPassword(savePassword.value);
                    derivedKeyCache = dk;
                    localStorage.setItem('e2hat_encrypted_keys', JSON.stringify({
                        dh: encryptKey(dhPrivateKey.value, dk),
                        mo: encryptKey(moPrivateKey.value, dk),
                    }));
                    localStorage.setItem('e2hat_nickname', nickname.value);
                    keysSaved.value = true;
                    hasSavedKeys.value = true;
                    status.value = 'Keys saved encrypted';
                    log('Keys saved');
                } catch (e) { status.value = 'Error: ' + e.message; }
            }, 50);
        }

        function restoreKeys() {
            if (!restorePassword.value.trim()) return;
            status.value = 'Decrypting keys...';
            setTimeout(() => {
                try {
                    const data = JSON.parse(localStorage.getItem('e2hat_encrypted_keys'));
                    const dk = deriveKeyFromPassword(restorePassword.value);
                    const dhKey = decryptKey(data.dh, dk);
                    const moKey = decryptKey(data.mo, dk);
                    const dh = new DiffieHellman(dhKey, CURVE_NAME);
                    dhPrivateKey.value = dhKey;
                    dhPublicKey.value = dh.publicKey;
                    moPrivateKey.value = moKey;
                    moInstance.value = new MasseyOmura(moKey, CURVE_NAME);
                    const [x, parity] = dhPublicKey.value.compress();
                    myPubKeyHex.value = pointToHex(x, parity);
                    derivedKeyCache = dk;
                    loadMessages(dk);
                    nickname.value = localStorage.getItem('e2hat_nickname') || '';
                    restoredKeys.value = true;
                    keysSaved.value = true;
                    status.value = 'Keys restored!';
                    log('Keys restored');
                } catch {
                    status.value = 'Wrong password or corrupted data';
                }
            }, 50);
        }

        function clearSavedKeys() {
            localStorage.removeItem('e2hat_encrypted_keys');
            localStorage.removeItem('e2hat_encrypted_messages');
            hasSavedKeys.value = false;
            restoredKeys.value = false;
            restorePassword.value = '';
            status.value = '';
        }

        // --- Enter chat (no auto-connect, user manages servers) ---
        function enterChat() {
            if (!nickname.value.trim() || !dhPublicKey.value) return;
            localStorage.setItem('e2hat_nickname', nickname.value);
            screen.value = 'chat';
            view.value = servers.length ? 'contacts' : 'servers';
            log('Entered chat');
            // Auto-connect saved servers
            servers.forEach((_, i) => connectServer(i));
        }

        // === SERVER CONNECTION ===
        function connectServer(index) {
            const srv = servers[index];
            if (!srv || srv.state === 'connected' || srv.state === 'connecting') return;
            if (!dhPublicKey.value) return;

            srv.state = 'connecting';
            log(`[${srv.name}] Connecting to ${srv.url}...`);

            try {
                const ws = new WebSocket(srv.url);
                ws.binaryType = 'arraybuffer';
                srv.ws = ws;

                ws.onopen = () => {
                    log(`[${srv.name}] Connected`);
                    // Generate a fresh MO key per server connection
                    const moKey = randomMoKey();
                    srv.mo = new MasseyOmura(moKey, CURVE_NAME);
                    // Send HELLO
                    const [x, parity] = dhPublicKey.value.compress();
                    ws.send(P.packHello(x, parity));
                    log(`[${srv.name}] >> HELLO`);
                };

                ws.onmessage = (event) => {
                    handleServerMessage(index, new Uint8Array(event.data));
                };

                ws.onclose = () => {
                    log(`[${srv.name}] Disconnected`);
                    srv.state = 'disconnected';
                    srv.ws = null;
                    srv.onlinePeers.clear();
                };

                ws.onerror = () => {
                    log(`[${srv.name}] Connection error`);
                    srv.state = 'disconnected';
                };
            } catch (e) {
                log(`[${srv.name}] Failed: ${e.message}`);
                srv.state = 'disconnected';
            }
        }

        function disconnectServer(index) {
            const srv = servers[index];
            if (srv.ws) { srv.ws.close(); srv.ws = null; }
            srv.state = 'disconnected';
            srv.onlinePeers.clear();
            log(`[${srv.name}] Manually disconnected`);
        }

        // === PROTOCOL HANDLER (per server) ===
        function handleServerMessage(srvIdx, data) {
            const srv = servers[srvIdx];
            const { msgType, payload } = P.unpackFrame(data);
            const typeName = {
                [P.WELCOME]: 'WELCOME', [P.MO_SEND_STEP2]: 'MO_SEND_STEP2',
                [P.MO_RECV_INIT]: 'MO_RECV_INIT', [P.MO_RECV_STEP3]: 'MO_RECV_STEP3',
                [P.ERROR]: 'ERROR', [P.PEER_ONLINE]: 'PEER_ONLINE', [P.PEER_OFFLINE]: 'PEER_OFFLINE',
                [P.MSG_ACK]: 'MSG_ACK', [P.MSG_DELIVERED]: 'MSG_DELIVERED', [P.MSG_QUEUED]: 'MSG_QUEUED',
            }[msgType] || `0x${msgType.toString(16)}`;
            log(`[${srv.name}] << ${typeName}`);

            switch (msgType) {
                case P.WELCOME: {
                    P.unpackWelcome(payload); // parse for logging
                    srv.state = 'connected';
                    log(`[${srv.name}] Handshake complete`);
                    break;
                }
                case P.MO_SEND_STEP2: handleMoSendStep2(srvIdx, payload); break;
                case P.MO_RECV_INIT: handleMoRecvInit(srvIdx, payload); break;
                case P.MO_RECV_STEP3: handleMoRecvStep3(srvIdx, payload); break;
                case P.MSG_ACK: handleMsgStatus(payload, 'sent'); break;
                case P.MSG_DELIVERED: handleMsgStatus(payload, 'delivered'); break;
                case P.MSG_QUEUED: handleMsgStatus(payload, 'queued'); break;
                case P.ERROR: {
                    const code = P.unpackError(payload);
                    const names = { [P.ERR_USER_NOT_FOUND]: 'User not found', [P.ERR_INVALID_FRAME]: 'Invalid frame', [P.ERR_SESSION_EXPIRED]: 'Session expired' };
                    log(`[${srv.name}] ERROR: ${names[code] || code}`);
                    break;
                }
                case P.PEER_ONLINE: {
                    const { x, parity } = P.unpackPeerEvent(payload);
                    const hex = pointToHex(x, parity);
                    srv.onlinePeers.add(hex);
                    const c = contacts.find(c => c.keyHex === hex);
                    log(`[${srv.name}] ${c ? c.nickname : hex.substring(0, 16) + '...'} online`);
                    break;
                }
                case P.PEER_OFFLINE: {
                    const { x, parity } = P.unpackPeerEvent(payload);
                    const hex = pointToHex(x, parity);
                    srv.onlinePeers.delete(hex);
                    const c = contacts.find(c => c.keyHex === hex);
                    log(`[${srv.name}] ${c ? c.nickname : hex.substring(0, 16) + '...'} offline`);
                    break;
                }
            }
        }

        /** MO send step 2: server returned C2 = server_mo.encrypt(C1).
         *  We compute C3 = our_mo.decrypt(C2) and send it back.
         *  After this, the server can decrypt C3 to obtain E. */
        function handleMoSendStep2(srvIdx, payload) {
            const srv = servers[srvIdx];
            const { sessionId, x, parity } = P.unpackMoSendStep2(payload);

            let session = pendingSendSessions[sessionId];
            if (!session && pendingSendSessions['_next_send_' + srvIdx]) {
                session = pendingSendSessions['_next_send_' + srvIdx];
                delete pendingSendSessions['_next_send_' + srvIdx];
                pendingSendSessions[sessionId] = session;
            }
            if (!session) { log(`  Session ${sessionId} not found`); return; }

            const c2Point = Point.decompress(x, parity, curve);
            const c3Point = session.moInstance.decrypt(c2Point);
            const [c3X, c3Parity] = c3Point.compress();

            log(`[${srv.name}] >> MO_SEND_STEP3`);
            srv.ws.send(P.packMoSendStep3(sessionId, c3X, c3Parity));

            if (session.msgIndex !== undefined) {
                sentMessageMap[sessionId] = { destHex: session.destHex, msgIndex: session.msgIndex };
            }
            delete pendingSendSessions[sessionId];
        }

        /** MO receive step 1: server sent C1' = server_mo.encrypt(E).
         *  We compute C2' = our_mo.encrypt(C1') and send it back. */
        function handleMoRecvInit(srvIdx, payload) {
            const srv = servers[srvIdx];
            const { sessionId, senderX, senderParity, j, c1X, c1Parity } = P.unpackMoRecvInit(payload);
            const senderHex = pointToHex(senderX, senderParity);

            const c1Point = Point.decompress(c1X, c1Parity, curve);
            const c2Point = srv.mo.encrypt(c1Point);
            const [c2X, c2Parity] = c2Point.compress();

            pendingRecvSessions[sessionId] = { serverIndex: srvIdx, moInstance: srv.mo, senderHex, j };

            log(`[${srv.name}] >> MO_RECV_STEP2`);
            srv.ws.send(P.packMoRecvStep2(sessionId, c2X, c2Parity));
        }

        /** MO receive step 3: server sent C3' = server_mo.decrypt(C2').
         *  We compute E = our_mo.decrypt(C3'), then DH-decrypt and Koblitz-decode
         *  to recover the plaintext message. */
        function handleMoRecvStep3(srvIdx, payload) {
            const srv = servers[srvIdx];
            const { sessionId, x, parity } = P.unpackMoRecvStep3(payload);

            const session = pendingRecvSessions[sessionId];
            if (!session) { log(`  Session ${sessionId} not found`); return; }

            const c3Point = Point.decompress(x, parity, curve);
            const ePoint = session.moInstance.decrypt(c3Point);

            const senderPt = hexToPoint(session.senderHex);
            const senderPubKey = Point.decompress(senderPt.x, senderPt.parity, curve);
            const dh = new DiffieHellman(dhPrivateKey.value, CURVE_NAME);
            const shared = dh.computeSharedSecret(senderPubKey);
            const invX = modInverse(shared.x, curve.n);
            const mPoint = ePoint.mul(invX);
            const text = koblitz.decode(mPoint, session.j);

            ensureContact(session.senderHex);

            if (!messages[session.senderHex]) messages[session.senderHex] = [];
            messages[session.senderHex].push({ text, sent: false, time: new Date().toLocaleTimeString() });
            saveMessages();

            const viewing = activeContact.value && activeContact.value.keyHex === session.senderHex && view.value === 'chat';
            if (!viewing) unreadMessages[session.senderHex] = (unreadMessages[session.senderHex] || 0) + 1;

            delete pendingRecvSessions[sessionId];
            const c = contacts.find(c => c.keyHex === session.senderHex);
            log(`[${srv.name}] Message from ${c ? c.nickname : '?'}: "${text.substring(0, 40)}..."`);
            scrollMessages();
        }

        function handleMsgStatus(payload, newStatus) {
            const sid = P.unpackSessionId(payload);
            const info = sentMessageMap[sid];
            if (!info) return;
            const msgList = messages[info.destHex];
            if (msgList && msgList[info.msgIndex]) {
                msgList[info.msgIndex].status = newStatus;
                saveMessages();
            }
            if (newStatus === 'delivered') delete sentMessageMap[sid];
        }

        // === SEND MESSAGE ===
        /** Encrypt and send a message to the active contact.
         *  Steps: Koblitz encode -> DH encrypt -> MO encrypt -> send to server */
        function sendMessage() {
            if (!messageInput.value.trim() || !activeContact.value) return;
            const text = messageInput.value.trim();
            const destHex = activeContact.value.keyHex;

            const srvIdx = findServerForPeer(destHex);
            if (srvIdx < 0) { log('No connected server available'); return; }
            const srv = servers[srvIdx];

            const [mPoint, j] = koblitz.encode(text);
            const destPt = hexToPoint(destHex);
            const destPubKey = Point.decompress(destPt.x, destPt.parity, curve);
            const dh = new DiffieHellman(dhPrivateKey.value, CURVE_NAME);
            const shared = dh.computeSharedSecret(destPubKey);
            const ePoint = mPoint.mul(shared.x);
            const c1Point = srv.mo.encrypt(ePoint);
            const [c1X, c1Parity] = c1Point.compress();

            if (!messages[destHex]) messages[destHex] = [];
            const msgIndex = messages[destHex].length;
            messages[destHex].push({ text, sent: true, time: new Date().toLocaleTimeString(), status: 'sending' });
            saveMessages();

            pendingSendSessions['_next_send_' + srvIdx] = { moInstance: srv.mo, destHex, j, msgIndex };

            log(`[${srv.name}] >> MO_SEND_INIT to ${activeContact.value.nickname}`);
            srv.ws.send(P.packMoSendInit(destPt.x, destPt.parity, j, c1X, c1Parity));

            messageInput.value = '';
            scrollMessages();
        }

        // === SERVER MANAGEMENT ===
        function addServer() {
            const name = newServerName.value.trim();
            let url = newServerUrl.value.trim();
            if (!name || !url) return;
            if (!url.startsWith('ws://') && !url.startsWith('wss://')) {
                url = 'ws://' + url;
            }
            if (!url.endsWith('/ws')) {
                url = url.replace(/\/$/, '') + '/ws';
            }
            if (servers.find(s => s.url === url)) { log('Server already exists'); return; }
            servers.push({ name, url, state: 'disconnected', ws: null, mo: null, onlinePeers: new Set() });
            saveServers();
            newServerName.value = '';
            newServerUrl.value = '';
            log(`Server added: ${name}`);
            // Auto-connect if in chat
            if (screen.value === 'chat') connectServer(servers.length - 1);
        }

        function removeServer(index) {
            disconnectServer(index);
            const s = servers[index];
            log(`Server removed: ${s.name}`);
            servers.splice(index, 1);
            saveServers();
        }

        // === CONTACT MANAGEMENT ===
        function addContact() {
            const nick = newContactNick.value.trim();
            const key = newContactKey.value.trim();
            if (!nick || !key || !key.includes(':')) { log('Invalid contact'); return; }
            if (contacts.find(c => c.keyHex === key)) { log('Contact already exists'); return; }
            contacts.push({ nickname: nick, keyHex: key });
            saveContacts();
            newContactNick.value = '';
            newContactKey.value = '';
            log(`Contact added: ${nick}`);
        }

        function removeContact(index) {
            const c = contacts[index];
            log(`Contact removed: ${c.nickname}`);
            contacts.splice(index, 1);
            saveContacts();
            if (activeContact.value && activeContact.value.keyHex === c.keyHex) activeContact.value = null;
        }

        function startEditContact(index) {
            editingContact.value = index;
            nextTick(() => {
                const inputs = document.querySelectorAll('.contact-edit-input');
                if (inputs.length) inputs[0].focus();
            });
        }

        function finishEditContact(index, newName) {
            const trimmed = newName.trim();
            if (trimmed && contacts[index]) {
                contacts[index].nickname = trimmed;
                saveContacts();
            }
            editingContact.value = null;
        }

        function ensureContact(keyHex) {
            if (contacts.find(c => c.keyHex === keyHex)) return;
            const shortKey = keyHex.substring(0, 12) + '...';
            contacts.push({ nickname: `Unknown (${shortKey})`, keyHex });
            saveContacts();
            log(`Unknown sender added: ${shortKey}`);
        }

        function selectContact(contact) {
            if (editingContact.value !== null) return;
            activeContact.value = contact;
            unreadMessages[contact.keyHex] = 0;
            view.value = 'chat';
            scrollMessages();
        }

        function logout() {
            servers.forEach((_, i) => disconnectServer(i));
            screen.value = 'setup';
            status.value = '';
            log('Logged out');
        }

        function scrollMessages() {
            nextTick(() => { if (messagesEl.value) messagesEl.value.scrollTop = messagesEl.value.scrollHeight; });
        }

        watch(activeContact, (c) => {
            if (c && view.value === 'chat') unreadMessages[c.keyHex] = 0;
        });

        return {
            screen, view, showServers, nickname, status, logs,
            compressedPubKeyDisplay, copied,
            servers, contacts, activeContact, activeMessages,
            messageInput, messagesEl, logEl,
            newContactNick, newContactKey, editingContact,
            newServerName, newServerUrl, showAddContact, showAddServer,
            logHeight,
            hasSavedKeys, restoredKeys, restorePassword, savePassword, keysSaved,
            generateKeys, enterChat, sendMessage, logout,
            addServer, removeServer, connectServer, disconnectServer,
            addContact, removeContact, selectContact,
            startEditContact, finishEditContact,
            isOnline, unreadCount, startLogResize,
            copyPubKey, saveKeys, restoreKeys, clearSavedKeys,
        };
    },
}).mount('#app');
