/**
 * e2hat - End-to-end encrypted chat with elliptic curves.
 *
 * Cryptographic flow for sending a message:
 *   1. Koblitz.encode(nonce + text) -> (M, j)   Text becomes a curve point (nonce for non-determinism)
 *   2. scalar = HKDF(DH(privA,pubB).x, ts:dest:j)  Derive per-message scalar via HKDF-SHA256
 *   3. E = M * scalar                           Encrypt with derived scalar
 *   4. ECDSA.signMessage(E.x:eParity:j:ts:dest) Sign for authentication and anti-replay
 *   5. C1 = mo.encrypt(E)                       MO layer for transit to server
 *   6. Server 3-pass (SEND_INIT/STEP2/STEP3)    Server receives E without seeing M
 *   7. Server 3-pass (RECV_INIT/STEP2/STEP3)    Receiver gets E + signature
 *   8. ECDSA.verifyMessage(sig, sender_pubkey)   Verify authenticity
 *   9. M = E * modInverse(scalar, n)            Decrypt with inverse of derived scalar
 *  10. Koblitz.decode(M, j) -> nonce + text      Curve point becomes text (strip nonce)
 *
 * The server only ever sees E (encrypted with DH). It cannot derive the DH
 * shared secret because it doesn't have either party's private key.
 *
 * Multi-server: the frontend connects to multiple relay servers simultaneously.
 * Each server has its own MO key pair and WebSocket connection.
 *
 * Ephemeral key exchange (forward secrecy):
 *   When both peers are online, they negotiate ephemeral DH key pairs via
 *   in-band messages (marker \x02) sent through the existing MO 3-pass flow.
 *   Transit encryption uses the ephemeral shared secret; at-rest storage always
 *   re-encrypts under the permanent identity DH shared secret so messages
 *   survive key rotation on reload. The server sees no difference — key exchange
 *   messages are indistinguishable from regular encrypted traffic.
 *
 * Storage model:
 *   Messages are stored in IndexedDB as encrypted curve points (e_x, e_parity, j),
 *   never as plaintext. On load, text is re-derived: M = E * scalar⁻¹, then
 *   Koblitz.decode(M, j). Identity keys (DH, MO) and ephemeral private keys are
 *   stored encrypted with AES-GCM derived from the user's password (PBKDF2).
 */

const { createApp, ref, reactive, computed, nextTick, watch } = Vue;
const { Point, DiffieHellman, MasseyOmura, Koblitz, DigitalSignature, getCurve } = ecutils;

const CURVE_NAME = 'secp521r1';
const curve = getCurve(CURVE_NAME);
const P = Protocol;

// --- Cryptographic utilities ---

/** Generate a random 4-char string (nonce) for message padding */
function generateNonce() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const randomVals = new Uint8Array(4);
    crypto.getRandomValues(randomVals);
    for (let i = 0; i < 4; i++) {
        result += chars[randomVals[i] % chars.length];
    }
    return result;
}

/** Generate a random private key in range [2, n-1] for secp521r1. */
function randomPrivateKey() {
    while (true) {
        const bytes = new Uint8Array(66);
        crypto.getRandomValues(bytes);
        bytes[0] &= 0x01; // mask to 521 bits
        let k = 0n;
        for (const b of bytes) k = (k << 8n) | BigInt(b);
        if (k >= 2n && k < curve.n) return k;
    }
}

/** Greatest common divisor (Euclidean algorithm). Used to ensure MO keys are coprime with n. */
function gcd(a, b) {
    a = a < 0n ? -a : a;
    b = b < 0n ? -b : b;
    while (b > 0n) { [a, b] = [b, a % b]; }
    return a;
}

/** Random key coprime with n for Massey-Omura. */
function randomMoKey() {
    while (true) {
        const k = randomPrivateKey();
        if (gcd(k, curve.n) === 1n) return k;
    }
}

/** Compressed point -> "hex_x:parity" identifier. */
function pointToHex(x, parity) {
    return x.toString(16).padStart(132, '0') + ':' + parity.toString();
}

/** "hex_x:parity" -> {x, parity} BigInts. */
function hexToPoint(hex) {
    const parts = hex.split(':');
    return { x: BigInt('0x' + parts[0]), parity: BigInt(parts[1]) };
}

/** Modular inverse via Fermat's little theorem: a⁻¹ = a^(m-2) mod m (m must be prime). */
function modInverse(a, m) {
    a = ((a % m) + m) % m;
    let result = 1n;
    let base = a;
    let exp = m - 2n;
    while (exp > 0n) {
        if (exp & 1n) result = result * base % m;
        exp >>= 1n;
        base = base * base % m;
    }
    return result;
}

// --- HKDF: derive scalar from DH shared secret (RFC 5869 / NIST SP 800-56A) ---

/** Derive a per-message curve scalar from DH shared secret via HKDF-SHA256.
 *  The info string binds the derivation to the specific message context:
 *  - timestampMs: per-message uniqueness (breaks algebraic E_i/E_j = M_i/M_j)
 *  - destHex: binds to recipient identity
 *  - j: binds to Koblitz encoding parameter */
async function deriveScalar(sharedX, timestampMs, destHex, j) {
    const sharedBytes = bigintToFixedBytes(sharedX, 66); // 521-bit key -> 66 bytes
    const hkdfKey = await crypto.subtle.importKey('raw', sharedBytes, 'HKDF', false, ['deriveBits']);
    const info = new TextEncoder().encode(`e2hat:${timestampMs}:${destHex}:${j}`);
    const derived = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(66), info },
        hkdfKey, 592 // derive 592 bits (521 + 71), then reduce mod n — bias < 2^-71 per FIPS 186-4
    );
    const raw = BigInt('0x' + bytesToHex(new Uint8Array(derived)));
    return (raw % (curve.n - 1n)) + 1n; // ensure [1, n-1]
}

// --- Key derivation and encryption (AES-GCM) ---

/** Hex string -> Uint8Array */
function hexToBytes(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

/** Uint8Array -> hex string */
function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/** PBKDF2-HMAC-SHA256(password, salt) -> AES-GCM CryptoKey + salt hex */
async function deriveAesKey(password, saltHex) {
    const encoder = new TextEncoder();
    const passKey = await crypto.subtle.importKey(
        'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
    const aesKey = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
        passKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    return { aesKey, salt: bytesToHex(salt) };
}

/** Encrypt plaintext bytes with AES-GCM. Returns {iv, ciphertext} as hex. */
async function aesGcmEncrypt(aesKey, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);
    return { iv: bytesToHex(iv), ciphertext: bytesToHex(new Uint8Array(ct)) };
}

/** Decrypt AES-GCM ciphertext. Returns plaintext Uint8Array. */
async function aesGcmDecrypt(aesKey, ivHex, ciphertextHex) {
    const iv = hexToBytes(ivHex);
    const ct = hexToBytes(ciphertextHex);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
    return new Uint8Array(pt);
}

/** Encode a BigInt private key as fixed-length bytes for AES-GCM encryption. */
function bigintToFixedBytes(value, len = 66) {
    const hex = value.toString(16).padStart(len * 2, '0');
    return hexToBytes(hex);
}

/** Decode fixed-length bytes back to BigInt. */
function fixedBytesToBigint(bytes) {
    return BigInt('0x' + bytesToHex(bytes));
}

// --- IndexedDB storage ---

const DB_NAME = 'e2hat';
const DB_VERSION = 2;
let _db = null;

function openDB() {
    if (_db) return Promise.resolve(_db);
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = (e) => {
            const db = e.target.result;
            for (const name of ['config', 'keys', 'messages', 'replayGuard']) {
                if (!db.objectStoreNames.contains(name)) db.createObjectStore(name);
            }
        };
        req.onsuccess = () => { _db = req.result; resolve(_db); };
        req.onerror = () => reject(req.error);
    });
}

async function idbGet(store, key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(store, 'readonly');
        const req = tx.objectStore(store).get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function idbPut(store, key, value) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(store, 'readwrite');
        const req = tx.objectStore(store).put(value, key);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
    });
}

async function idbDel(store, key) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(store, 'readwrite');
        const req = tx.objectStore(store).delete(key);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
    });
}

async function idbGetAllKeys(store) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(store, 'readonly');
        const req = tx.objectStore(store).getAllKeys();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function idbClear(store) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(store, 'readwrite');
        const req = tx.objectStore(store).clear();
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
    });
}

createApp({
    setup() {
        const screen = ref('setup');
        const view = ref('contacts');
        const showServers = ref(true);
        const nickname = ref('');
        const status = ref('');
        const logs = ref([]);

        const dhPrivateKey = ref(null);
        const dhPublicKey = ref(null);
        const moPrivateKey = ref(null);
        const myPubKeyHex = ref('');

        const DEFAULT_SERVERS = [
            { name: 'Local', url: 'wss://relay.e2hat.com/ws' },
        ];
        const DEFAULT_CONTACT = {
            nickname: 'e2hat team',
            keyHex: '00f33fb6a24290ee1d534ff3fd0976786bba24b18880220dce644a21fdc030e3c367fcaf37031f2f2afe68df77f0c4a7c708d7963c78c993683a87f0fbb401be222d:1'
        };

        const servers = reactive([]);
        const contacts = reactive([]);
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

        // --- MO session tracking ---
        // pendingSendSessions: sessionId -> {moInstance, destHex, j, msgIndex, srvIdx, _resolve}
        // pendingSendQueues: srvIdx -> FIFO of sessions awaiting server-assigned session ID
        // pendingRecvSessions: sessionId -> {serverIndex, moInstance, senderHex, j, sigR, sigS, timestampMs}
        // sentMessageMap: sessionId -> {destHex, msgIndex, ts} for tracking delivery status
        const pendingSendSessions = reactive({});
        const pendingSendQueues = {};
        const pendingRecvSessions = reactive({});
        const sentMessageMap = reactive({});
        const retryQueues = {};
        const seenSignatures = new Map(); // Anti-replay: sig fingerprint → timestamp
        const REPLAY_MAX_AGE = 5 * 60 * 1000; // 5 min window for replay detection
        let _replayPersistTimer = null;
        /** Debounced persistence of replay guard to IndexedDB (1s delay to batch writes). */
        function persistReplayGuard() {
            if (_replayPersistTimer) return;
            _replayPersistTimer = setTimeout(async () => {
                _replayPersistTimer = null;
                const obj = Object.fromEntries(seenSignatures);
                await idbPut('replayGuard', 'signatures', obj);
            }, 1000);
        }
        function flushReplayGuardNow() {
            if (_replayPersistTimer) clearTimeout(_replayPersistTimer);
            _replayPersistTimer = null;
            const obj = Object.fromEntries(seenSignatures);
            idbPut('replayGuard', 'signatures', obj);
        }
        window.addEventListener('beforeunload', flushReplayGuardNow);
        // pendingMultiparts: "senderHex:groupId" -> {total, parts: {idx: text}, senderHex, msgIndex, ...}
        const pendingMultiparts = {};

        // --- Ephemeral DH key state ---
        // ephemeralKeys[contactHex] = {
        //   myPriv: BigInt,           — my ephemeral private key
        //   myPubX: BigInt,           — my ephemeral public key X coordinate
        //   myPubParity: BigInt,      — my ephemeral public key parity (0 or 1)
        //   peerPubX: BigInt|null,    — peer's ephemeral public key X (null until received)
        //   peerPubParity: BigInt|null,
        //   state: 'initiated'|'complete',
        //   negotiatedAt: number,     — Date.now() when exchange completed
        //   generation: number,       — monotonic counter for rekey cycles
        // }
        const ephemeralKeys = reactive({});
        let _ephemeralAesKey = null; // cached AES-GCM key (derived from user password) for encrypting ephemeral privkeys in IDB

        const koblitz = new Koblitz(CURVE_NAME);
        const messagesEl = ref(null);
        const logEl = ref(null);
        const logHeight = ref(80);
        const copied = ref(false);
        let copiedTimeout = null;

        const hasSavedKeys = ref(false);
        const restoredKeys = ref(false);
        const restorePassword = ref('');
        const savePassword = ref('');
        const keysSaved = ref(false);

        // Load persisted state from IndexedDB
        (async () => {
            try {
                const [savedNick, savedServers, savedContacts, savedKeys] = await Promise.all([
                    idbGet('config', 'nickname'),
                    idbGet('config', 'servers'),
                    idbGet('config', 'contacts'),
                    idbGet('keys', 'encrypted'),
                ]);
                if (savedNick) nickname.value = savedNick;
                hasSavedKeys.value = !!savedKeys;
                const srvList = savedServers || DEFAULT_SERVERS;
                srvList.forEach(s => servers.push({
                    name: s.name, url: s.url, state: 'disconnected',
                    ws: null, mo: null, onlinePeers: new Set(),
                }));
                const contactList = savedContacts || [];
                if (!contactList.find(c => c.keyHex === DEFAULT_CONTACT.keyHex)) {
                    contactList.unshift(DEFAULT_CONTACT);
                }
                contactList.forEach(c => contacts.push(c));
                // Restore replay guard from IndexedDB
                try {
                    const stored = await idbGet('replayGuard', 'signatures');
                    if (stored) {
                        const now = Date.now();
                        for (const [fp, ts] of Object.entries(stored)) {
                            if (now - ts <= REPLAY_MAX_AGE) seenSignatures.set(fp, ts);
                        }
                    }
                } catch (_e) { /* replayGuard store may not exist yet */ }
            } catch (e) {
                console.error('Failed to load from IndexedDB:', e);
                // Fallback: add defaults
                DEFAULT_SERVERS.forEach(s => servers.push({
                    name: s.name, url: s.url, state: 'disconnected',
                    ws: null, mo: null, onlinePeers: new Set(),
                }));
                contacts.push(DEFAULT_CONTACT);
            }
        })();

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

        // --- Persistence (IndexedDB) ---

        /** Strip volatile/runtime fields before persisting a message to IndexedDB.
         *  If the message has e_x (encrypted curve point), also strip the plaintext —
         *  it will be re-derived from e_x on reload via identity DH + HKDF. */
        function cleanMsgForStorage(m) {
            if (m.e_x) { const { text: _text, _blobUrl, _receiving, _multipartDone, ...rest } = m; return rest; }
            const { _blobUrl, _receiving, _multipartDone, ...rest } = m;
            return rest;
        }

        /** Persist messages to IndexedDB. If contactHex given, saves only that conversation. */
        function saveMessages(contactHex) {
            if (contactHex) {
                const list = (messages[contactHex] || []).map(cleanMsgForStorage);
                idbPut('messages', contactHex, list);
            } else {
                for (const key of Object.keys(messages)) {
                    const list = messages[key].map(cleanMsgForStorage);
                    idbPut('messages', key, list);
                }
            }
        }

        const MSG_TTL = 365 * 24 * 60 * 60 * 1000; // 1 year in ms

        /** Reload messages from IndexedDB, re-deriving plaintext from stored curve points.
         *  Each stored message has e_x (encrypted point E), e_parity, j, and sigTs/ts.
         *  Decryption: scalar = HKDF(identityDH.x, ts, dest, j), M = E * scalar⁻¹, text = Koblitz.decode(M, j).
         *  e_x is always encrypted with identity keys (not ephemeral), so this survives rekey cycles. */
        async function loadMessages() {
            const keys = await idbGetAllKeys('messages');
            if (!keys.length) return;
            const now = Date.now();
            const invCache = {}; // contactHex -> identity DH shared secret X (cached across messages)
            let totalLoaded = 0;
            let totalExpired = 0;
            const BATCH_SIZE = 5; // decrypt N messages per tick to avoid CPU spike

            function yieldToUI() {
                return new Promise(resolve => setTimeout(resolve, 0));
            }

            for (const contactHex of keys) {
                const msgList = await idbGet('messages', contactHex);
                if (!msgList) continue;
                const fresh = msgList.filter(m => {
                    if (m.ts && now - m.ts > MSG_TTL) { totalExpired++; return false; }
                    return true;
                });
                if (fresh.length < msgList.length) {
                    if (fresh.length === 0) { idbDel('messages', contactHex); continue; }
                    idbPut('messages', contactHex, fresh);
                }
                // Load messages: text/media immediately, encrypted text in batches
                const result = new Array(fresh.length);
                let decryptCount = 0;
                for (let i = 0; i < fresh.length; i++) {
                    const m = fresh[i];
                    if (m.text) {
                        result[i] = { ...m }; // already has text (multipart/media)
                    } else if (!m.e_x) {
                        result[i] = { ...m, text: '[unreadable]' };
                    } else {
                        try {
                            // e_x is always stored encrypted with identity keys (survives ephemeral rekey)
                            if (!invCache[contactHex]) {
                                const pt = hexToPoint(contactHex);
                                const pubKey = Point.decompress(pt.x, pt.parity, curve);
                                const dh = new DiffieHellman(dhPrivateKey.value, CURVE_NAME);
                                invCache[contactHex] = dh.computeSharedSecret(pubKey).x;
                            }
                            const sharedX = invCache[contactHex];
                            // For sent messages, dest=contactHex; for received, dest=me
                            const hkdfDest = m.sent ? contactHex : myPubKeyHex.value;
                            // Use original sender timestamp (sigTs) if available, else ts
                            const hkdfTs = m.sigTs || m.ts;
                            const scalar = await deriveScalar(sharedX, hkdfTs, hkdfDest, m.j);
                            const invScalar = modInverse(scalar, curve.n);
                            const ePoint = Point.decompress(BigInt('0x' + m.e_x), BigInt(m.e_parity), curve);
                            const mPoint = ePoint.mul(invScalar);
                            let decoded = koblitz.decode(mPoint, m.j);
                            if (m.nonce) decoded = decoded.substring(NONCE_LEN);
                            result[i] = { ...m, text: decoded };
                        } catch {
                            result[i] = { ...m, text: '[decrypt error]' };
                        }
                        decryptCount++;
                        if (decryptCount % BATCH_SIZE === 0) {
                            await yieldToUI();
                        }
                    }
                }
                messages[contactHex] = result;
                totalLoaded += result.length;
                await yieldToUI(); // yield between contacts
            }
            log(`Messages restored: ${totalLoaded} messages across ${keys.length} conversations${totalExpired ? ` (${totalExpired} expired, removed)` : ''}`);
        }

        function saveServers() {
            idbPut('config', 'servers', servers.map(s => ({ name: s.name, url: s.url })));
        }

        function saveContacts() {
            idbPut('config', 'contacts', contacts.map(c => ({ keyHex: c.keyHex, nickname: c.nickname })));
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

                const [x, parity] = dhPublicKey.value.compress();
                myPubKeyHex.value = pointToHex(x, parity);
                status.value = 'Keys generated!';
                log(`DH and MO key pairs generated (pub: ${myPubKeyHex.value.substring(0, 16)}...)`);
            }, 50);
        }

        /** Encrypt identity keys (DH + MO) with user password via PBKDF2 → AES-GCM, save to IndexedDB. */
        function saveKeys() {
            if (!savePassword.value.trim() || !dhPrivateKey.value || !moPrivateKey.value) return;
            status.value = 'Encrypting keys...';
            setTimeout(async () => {
                try {
                    const { aesKey, salt } = await deriveAesKey(savePassword.value);
                    _ephemeralAesKey = aesKey;
                    const dhEnc = await aesGcmEncrypt(aesKey, bigintToFixedBytes(dhPrivateKey.value));
                    const moEnc = await aesGcmEncrypt(aesKey, bigintToFixedBytes(moPrivateKey.value));
                    await idbPut('keys', 'encrypted', {
                        dh_iv: dhEnc.iv, dh_ct: dhEnc.ciphertext,
                        mo_iv: moEnc.iv, mo_ct: moEnc.ciphertext,
                        salt,
                    });
                    await idbPut('config', 'nickname', nickname.value);
                    keysSaved.value = true;
                    hasSavedKeys.value = true;
                    status.value = 'Keys saved encrypted';
                    log('Keys saved');
                } catch (e) { status.value = 'Error: ' + e.message; }
            }, 50);
        }

        /** Decrypt identity keys from IndexedDB using user password, then load ephemeral keys and messages. */
        function restoreKeys() {
            if (!restorePassword.value.trim()) return;
            status.value = 'Decrypting keys...';
            setTimeout(async () => {
                try {
                    const data = await idbGet('keys', 'encrypted');
                    if (!data) { status.value = 'No saved keys'; return; }
                    const { aesKey } = await deriveAesKey(restorePassword.value, data.salt);
                    _ephemeralAesKey = aesKey;
                    const dhBytes = await aesGcmDecrypt(aesKey, data.dh_iv, data.dh_ct);
                    const moBytes = await aesGcmDecrypt(aesKey, data.mo_iv, data.mo_ct);
                    const dhKey = fixedBytesToBigint(dhBytes);
                    const moKey = fixedBytesToBigint(moBytes);
                    const dh = new DiffieHellman(dhKey, CURVE_NAME);
                    dhPrivateKey.value = dhKey;
                    dhPublicKey.value = dh.publicKey;
                    moPrivateKey.value = moKey;

                    const [x, parity] = dhPublicKey.value.compress();
                    myPubKeyHex.value = pointToHex(x, parity);
                    await loadEphemeralKeys(aesKey);
                    await loadMessages();
                    const savedNick = await idbGet('config', 'nickname');
                    if (savedNick) nickname.value = savedNick;
                    restoredKeys.value = true;
                    keysSaved.value = true;
                    status.value = 'Keys restored!';
                    log('Keys restored');
                } catch {
                    status.value = 'Wrong password or corrupted data';
                }
            }, 50);
        }

        async function clearSavedKeys() {
            await idbDel('keys', 'encrypted');
            await idbClear('messages');
            hasSavedKeys.value = false;
            restoredKeys.value = false;
            restorePassword.value = '';
            status.value = '';
        }

        // --- Export / Import private keys ---
        function exportKeys() {
            if (!dhPrivateKey.value || !moPrivateKey.value) return;
            const data = JSON.stringify({
                dh: dhPrivateKey.value.toString(16),
                mo: moPrivateKey.value.toString(16),
                nickname: nickname.value,
            });
            const blob = new Blob([data], { type: 'application/json' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'e2hat-keys.json';
            a.click();
            URL.revokeObjectURL(a.href);
            log('Keys exported');
        }

        const importFileInput = ref(null);

        function triggerImport() {
            if (importFileInput.value) importFileInput.value.click();
        }

        function importKeys(event) {
            const file = event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = () => {
                try {
                    const data = JSON.parse(reader.result);
                    const dhKey = BigInt('0x' + data.dh);
                    const moKey = BigInt('0x' + data.mo);
                    const dh = new DiffieHellman(dhKey, CURVE_NAME);
                    dhPrivateKey.value = dhKey;
                    dhPublicKey.value = dh.publicKey;
                    moPrivateKey.value = moKey;
    
                    const [x, parity] = dhPublicKey.value.compress();
                    myPubKeyHex.value = pointToHex(x, parity);
                    if (data.nickname) nickname.value = data.nickname;
                    restoredKeys.value = true;
                    status.value = 'Keys imported!';
                    log('Keys imported from file');
                } catch {
                    status.value = 'Invalid key file';
                }
            };
            reader.readAsText(file);
            event.target.value = '';
        }

        // --- Notifications via Service Worker ---
        async function notifyNewMessage(senderName, text) {
            if (document.visibilityState === 'visible') return;
            if (Notification.permission !== 'granted') return;
            const body = text.length > 80 ? text.substring(0, 80) + '...' : text;
            try {
                const reg = await navigator.serviceWorker.ready;
                await reg.showNotification(senderName, { body, icon: './icon.svg', tag: 'e2hat-msg-' + Date.now(), renotify: true });
            } catch {
                try { new Notification(senderName, { body, icon: './icon.svg' }); } catch {}
            }
            if (navigator.setAppBadge) navigator.setAppBadge().catch(() => {});
        }

        function clearBadge() {
            if (navigator.clearAppBadge) navigator.clearAppBadge().catch(() => {});
        }

        // Reconnect servers when app comes back to foreground
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible') {
                clearBadge();
                if (screen.value === 'chat') {
                    servers.forEach((srv, i) => {
                        if (srv.state === 'disconnected' && !srv._manualDisconnect) {
                            srv._retries = 0;
                            connectServer(i);
                        }
                    });
                }
            }
        });

        // --- Enter chat ---
        function enterChat() {
            if (!nickname.value.trim() || !dhPublicKey.value) return;
            idbPut('config', 'nickname', nickname.value);
            screen.value = 'chat';
            view.value = servers.length ? 'contacts' : 'servers';
            log('Entered chat');
            // Request notification permission
            if ('Notification' in window && Notification.permission === 'default') {
                Notification.requestPermission();
            }
            // Auto-connect saved servers
            servers.forEach((_, i) => connectServer(i));
            // Periodic ephemeral key renegotiation: every 60s, check all online contacts
            // and re-initiate if their last negotiation exceeded REKEY_INTERVAL_MS.
            setInterval(() => {
                for (const c of contacts) {
                    if (!isOnline(c.keyHex)) continue;
                    const ek = ephemeralKeys[c.keyHex];
                    if (!ek || ek.state !== 'complete') continue;
                    if (Date.now() - ek.negotiatedAt > REKEY_INTERVAL_MS) {
                        const idx = findServerForPeer(c.keyHex);
                        if (idx >= 0) initiateEphemeralExchange(c.keyHex, idx);
                    }
                }
            }, 60000);
        }

        // === SERVER CONNECTION ===
        // Reconnection uses a Web Worker for timers so they fire even when the tab is backgrounded.
        // Exponential backoff: 2s, 4s, 8s, 16s, 30s (capped).
        const reconnectTimers = {};
        const timerWorkerBlob = new Blob([`
            const timers = {};
            self.onmessage = (e) => {
                const { action, id, delay } = e.data;
                if (action === 'start') {
                    clearTimeout(timers[id]);
                    timers[id] = setTimeout(() => { self.postMessage({ id }); delete timers[id]; }, delay);
                } else if (action === 'cancel') {
                    clearTimeout(timers[id]); delete timers[id];
                }
            };
        `], { type: 'application/javascript' });
        const timerWorker = new Worker(URL.createObjectURL(timerWorkerBlob));
        timerWorker.onmessage = (e) => {
            const index = e.data.id;
            delete reconnectTimers[index];
            const srv = servers[index];
            if (srv && screen.value === 'chat' && srv.state === 'disconnected' && !srv._manualDisconnect) {
                connectServer(index);
            }
        };

        function scheduleReconnect(index) {
            if (reconnectTimers[index]) return;
            const srv = servers[index];
            if (!srv || srv._manualDisconnect) return;
            const delay = Math.min(30000, 2000 * Math.pow(2, srv._retries || 0));
            srv._retries = (srv._retries || 0) + 1;
            log(`[${srv.name}] Reconnecting in ${Math.round(delay / 1000)}s...`);
            reconnectTimers[index] = true;
            timerWorker.postMessage({ action: 'start', id: index, delay });
        }

        /** Open WebSocket to relay server, send HELLO with our DH public key, handle MO protocol. */
        function connectServer(index) {
            const srv = servers[index];
            if (!srv || srv.state === 'connected' || srv.state === 'connecting') return;
            if (!dhPublicKey.value) return;

            srv.state = 'connecting';
            srv._manualDisconnect = false;
            log(`[${srv.name}] Connecting to ${srv.url}...`);

            try {
                const ws = new WebSocket(srv.url);
                ws.binaryType = 'arraybuffer';
                srv.ws = ws;

                ws.onopen = () => {
                    srv._retries = 0;
                    log(`[${srv.name}] WebSocket connected to ${srv.url}`);
                    const moKey = randomMoKey();
                    srv.mo = new MasseyOmura(moKey, CURVE_NAME);
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
                    delete pendingSendQueues[index];
                    scheduleReconnect(index);
                };

                ws.onerror = () => {
                    log(`[${srv.name}] Connection error`);
                    srv.state = 'disconnected';
                };
            } catch (e) {
                log(`[${srv.name}] Failed: ${e.message}`);
                srv.state = 'disconnected';
                scheduleReconnect(index);
            }
        }

        function disconnectServer(index) {
            const srv = servers[index];
            if (!srv) return;
            srv._manualDisconnect = true;
            if (reconnectTimers[index]) { timerWorker.postMessage({ action: 'cancel', id: index }); delete reconnectTimers[index]; }
            if (srv.ws) { srv.ws.close(); srv.ws = null; }
            srv.state = 'disconnected';
            srv.onlinePeers.clear();
            log(`[${srv.name}] Manually disconnected`);
        }

        /** Main protocol dispatcher — routes incoming binary frames to the appropriate handler. */
        async function handleServerMessage(srvIdx, data) {
            const srv = servers[srvIdx];
            if (!srv) return;
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
                    const wInfo = P.unpackWelcome(payload);
                    log(`[${srv.name}] Received challenge, generating ECDSA signature...`);

                    // Create digital signature instance with our DH private key
                    const signer = new DigitalSignature(dhPrivateKey.value, CURVE_NAME);

                    // Domain-separated signing: prefix challenge with AUTH: to prevent cross-context forgery
                    const challengeHex = Array.from(wInfo.challenge, b => b.toString(16).padStart(2, '0')).join('');
                    const authPayload = `AUTH:${challengeHex}`;
                    const [r, s] = await signer.signMessage(authPayload);
                    srv.ws.send(P.packAuth(r, s));
                    log(`[${srv.name}] >> AUTH sent`);

                    srv.state = 'connected';
                    log(`[${srv.name}] Handshake complete (MO pub ${wInfo.x.toString(16).substring(0, 12)}...)`);
                    // Retry 'sending' messages on this server
                    const retryItems = [];
                    for (const destHex of Object.keys(messages)) {
                        const msgList = messages[destHex];
                        for (let i = 0; i < msgList.length; i++) {
                            const m = msgList[i];
                            if (m.status === 'sending' && m.e_x) {
                                retryItems.push({ destHex, msgIndex: i, e_x: m.e_x, e_parity: m.e_parity, j: m.j, ts: m.ts });
                            }
                        }
                    }
                    if (retryItems.length) {
                        retryQueues[srvIdx] = retryItems;
                        log(`[${srv.name}] Retrying ${retryItems.length} pending message(s)`);
                        flushNextRetry(srvIdx);
                    }
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
                    const names = { [P.ERR_USER_NOT_FOUND]: 'User not found', [P.ERR_INVALID_FRAME]: 'Invalid frame', [P.ERR_SESSION_EXPIRED]: 'Session expired', [P.ERR_RATE_LIMITED]: 'Rate limited' };
                    log(`[${srv.name}] ERROR: ${names[code] || code}`);
                    if (code === P.ERR_RATE_LIMITED) {
                        srv._rateLimited = true;
                        setTimeout(() => { srv._rateLimited = false; }, 2000);
                    }
                    break;
                }
                case P.PEER_ONLINE: {
                    const { x, parity } = P.unpackPeerEvent(payload);
                    const hex = pointToHex(x, parity);
                    srv.onlinePeers.add(hex);
                    const c = contacts.find(c => c.keyHex === hex);
                    log(`[${srv.name}] Peer online: ${c ? c.nickname : hex.substring(0, 16) + '...'} (${srv.onlinePeers.size} peers)`);
                    if (c) {
                        initiateEphemeralExchange(hex, srvIdx);
                    }
                    break;
                }
                case P.PEER_OFFLINE: {
                    const { x, parity } = P.unpackPeerEvent(payload);
                    const hex = pointToHex(x, parity);
                    srv.onlinePeers.delete(hex);
                    const c = contacts.find(c => c.keyHex === hex);
                    log(`[${srv.name}] Peer offline: ${c ? c.nickname : hex.substring(0, 16) + '...'} (${srv.onlinePeers.size} peers)`);
                    break;
                }
            }
        }

        /** MO send step 2: strip our MO layer -> C3 = mo.decrypt(C2), send back. */
        function handleMoSendStep2(srvIdx, payload) {
            const srv = servers[srvIdx];
            if (!srv || !srv.ws) return;
            const { sessionId, x, parity } = P.unpackMoSendStep2(payload);

            let session = pendingSendSessions[sessionId];
            if (!session) {
                const queue = pendingSendQueues[srvIdx];
                if (queue && queue.length) {
                    session = queue.shift();
                    pendingSendSessions[sessionId] = session;
                }
            }
            if (!session) { log(`  Session ${sessionId} not found`); return; }

            const c2Point = Point.decompress(x, parity, curve);
            log(`[${srv.name}] MO received C2 from server (C2.x: ${c2Point.x.toString(16).substring(0, 16)}...)`);
            const c3Point = session.moInstance.decrypt(c2Point);
            log(`[${srv.name}] MO decrypt: C3 = mo.decrypt(C2) (C3.x: ${c3Point.x.toString(16).substring(0, 16)}...)`);
            const [c3X, c3Parity] = c3Point.compress();

            log(`[${srv.name}] >> MO_SEND_STEP3 (sid=${sessionId})`);
            srv.ws.send(P.packMoSendStep3(sessionId, c3X, c3Parity));

            if (session.msgIndex !== undefined) {
                sentMessageMap[sessionId] = { destHex: session.destHex, msgIndex: session.msgIndex, ts: Date.now() };
            }
            const retrySrvIdx = session.srvIdx;
            const resolveCallback = session._resolve;
            delete pendingSendSessions[sessionId];
            if (resolveCallback) resolveCallback();
            if (retrySrvIdx !== undefined) flushNextRetry(retrySrvIdx);
        }

        /** Drain one retry from the queue; next fires after step2 completes. */
        async function flushNextRetry(srvIdx) {
            const queue = retryQueues[srvIdx];
            if (!queue || !queue.length) return;
            const srv = servers[srvIdx];
            if (!srv || srv.state !== 'connected' || !srv.ws) return;

            const item = queue.shift();
            const destPt = hexToPoint(item.destHex);
            const ePoint = Point.decompress(BigInt('0x' + item.e_x), BigInt(item.e_parity), curve);
            const c1Point = srv.mo.encrypt(ePoint);
            const [c1X, c1Parity] = c1Point.compress();

            // Use original timestamp — E was encrypted with deriveScalar(shared.x, originalTs, dest, j)
            // Receiver needs the same ts to derive the same scalar for decryption
            const timestampMs = item.ts;
            const sigPayload = `${ePoint.x.toString(16)}:${item.e_parity}:${item.j}:${timestampMs}:${item.destHex}`;
            const signer = new DigitalSignature(dhPrivateKey.value, CURVE_NAME);
            const [sigR, sigS] = await signer.signMessage(sigPayload);

            if (!pendingSendQueues[srvIdx]) pendingSendQueues[srvIdx] = [];
            pendingSendQueues[srvIdx].push({
                moInstance: srv.mo, destHex: item.destHex, j: item.j,
                msgIndex: item.msgIndex, srvIdx,
            });

            const retryDest = contacts.find(c => c.keyHex === item.destHex);
            log(`[${srv.name}] >> MO_SEND_INIT (retry to ${retryDest ? retryDest.nickname : item.destHex.substring(0, 16) + '...'}, j=${item.j}, signed)`);
            srv.ws.send(P.packMoSendInit(destPt.x, destPt.parity, item.j, c1X, c1Parity, sigR, sigS, timestampMs));
        }

        /** MO recv step 1: add our MO layer -> C2' = mo.encrypt(C1'), send back. */
        function handleMoRecvInit(srvIdx, payload) {
            const srv = servers[srvIdx];
            if (!srv || !srv.ws) return;
            const { sessionId, senderX, senderParity, j, c1X, c1Parity, sigR, sigS, timestampMs } = P.unpackMoRecvInit(payload);
            const senderHex = pointToHex(senderX, senderParity);

            const c1Point = Point.decompress(c1X, c1Parity, curve);
            const recvSender = contacts.find(c => c.keyHex === senderHex);
            log(`[${srv.name}] MO received C1' from server (C1'.x: ${c1Point.x.toString(16).substring(0, 16)}..., from ${recvSender ? recvSender.nickname : senderHex.substring(0, 16) + '...'})`);
            const c2Point = srv.mo.encrypt(c1Point);
            log(`[${srv.name}] MO encrypt: C2' = mo.encrypt(C1') (C2'.x: ${c2Point.x.toString(16).substring(0, 16)}...)`);
            const [c2X, c2Parity] = c2Point.compress();

            pendingRecvSessions[sessionId] = { serverIndex: srvIdx, moInstance: srv.mo, senderHex, j, sigR, sigS, timestampMs };

            log(`[${srv.name}] >> MO_RECV_STEP2 (sid=${sessionId})`);
            srv.ws.send(P.packMoRecvStep2(sessionId, c2X, c2Parity));
        }

        /** Assemble multipart message and push to chat. */
        function flushMultipart(key, partial) {
            const mp = pendingMultiparts[key];
            if (!mp) return;
            if (mp.timer) clearTimeout(mp.timer);

            let fullText = '';
            let missingParts = 0;
            for (let i = 0; i < mp.total; i++) {
                if (mp.parts[i] !== undefined) {
                    fullText += mp.parts[i];
                } else {
                    missingParts++;
                }
            }
            if (missingParts > 0) {
                log(`Multipart assembly: ${missingParts} missing parts out of ${mp.total}`);
            }

            // Check for ephemeral key exchange after reassembly
            if (fullText.charAt(0) === EPHEMERAL_MARKER) {
                handleEphemeralMessage(fullText, mp.senderHex);
                // Remove placeholder from UI
                if (messages[mp.senderHex] && mp.msgIndex !== undefined) {
                    messages[mp.senderHex].splice(mp.msgIndex, 1);
                }
                delete pendingMultiparts[key];
                return;
            }

            // Validate base64 integrity for data URIs
            if (fullText.startsWith('data:') && fullText.includes(';base64,')) {
                const b64 = fullText.substring(fullText.indexOf(',') + 1);
                try { atob(b64.substring(0, 100)); } catch (e) {
                    log(`Multipart assembly: base64 CORRUPTED (${e.message}). ${mp.total} parts, ${fullText.length} chars`);
                }
            }

            ensureContact(mp.senderHex);
            if (!messages[mp.senderHex]) messages[mp.senderHex] = [];

            // Update the placeholder message instead of pushing a new one
            if (mp.msgIndex !== undefined && messages[mp.senderHex][mp.msgIndex]) {
                const msg = messages[mp.senderHex][mp.msgIndex];
                msg.text = fullText;
                msg.verified = mp.verified;
                msg.nonce = true;
                msg.time = mp.time;
                msg.ts = mp.ts;
                delete msg._receiving;
            } else {
                messages[mp.senderHex].push({
                    text: fullText, sent: false, time: mp.time, ts: mp.ts,
                    verified: mp.verified, nonce: true,
                });
            }
            saveMessages(mp.senderHex);

            const viewing = activeContact.value && activeContact.value.keyHex === mp.senderHex && view.value === 'chat';
            if (!viewing) unreadMessages[mp.senderHex] = (unreadMessages[mp.senderHex] || 0) + 1;

            const c = contacts.find(c => c.keyHex === mp.senderHex);
            const senderName = c ? c.nickname : mp.senderHex.substring(0, 16) + '...';
            const received = Object.keys(mp.parts).length;
            log(`Multipart assembled from ${senderName} (${received}/${mp.total} parts${partial ? ', partial' : ''}): "${fullText.substring(0, 50)}${fullText.length > 50 ? '...' : ''}"`);
            notifyNewMessage(senderName, fullText);
            scrollMessages();

            delete pendingMultiparts[key];
        }

        /** MO recv step 3: strip MO -> E, then DH decrypt -> M, Koblitz decode -> text. */
        async function handleMoRecvStep3(srvIdx, payload) {
            const srv = servers[srvIdx];
            if (!srv) return;
            const { sessionId, x, parity } = P.unpackMoRecvStep3(payload);

            const session = pendingRecvSessions[sessionId];
            if (!session) { log(`  Session ${sessionId} not found`); return; }

            const c3Point = Point.decompress(x, parity, curve);
            const ePoint = session.moInstance.decrypt(c3Point);
            log(`[${srv.name}] MO decrypt: E = mo.decrypt(C3') (E.x: ${ePoint.x.toString(16).substring(0, 16)}...)`);
            const [_recvEX, recvEParity] = ePoint.compress();

            // Verify ECDSA signature on E.x:eParity:j:timestamp:dest (hashed internally by verifyMessage)
            let verified = false;
            const senderPt = hexToPoint(session.senderHex);
            const senderPubKey = Point.decompress(senderPt.x, senderPt.parity, curve);
            if (session.sigR && session.sigS && session.timestampMs) {
                // Anti-replay: reject duplicate signatures
                const sigFingerprint = `${session.sigR.toString(16).substring(0, 32)}:${session.sigS.toString(16).substring(0, 32)}`;
                if (seenSignatures.has(sigFingerprint)) {
                    log(`[${srv.name}] REPLAY BLOCKED: duplicate signature detected, dropping message`);
                    delete pendingRecvSessions[sessionId];
                    return;
                }
                try {
                    const age = Date.now() - session.timestampMs;
                    const MAX_AGE = REPLAY_MAX_AGE;
                    const MAX_FUTURE = 60000; // 1 minute clock skew tolerance
                    if (age > MAX_AGE || age < -MAX_FUTURE) {
                        log(`[${srv.name}] ECDSA: timestamp out of window (age: ${Math.round(age / 1000)}s), rejecting`);
                    } else {
                        const sigPayload = `${ePoint.x.toString(16)}:${recvEParity}:${session.j}:${session.timestampMs}:${myPubKeyHex.value}`;
                        const verifier = new DigitalSignature(1n, CURVE_NAME);
                        verified = await verifier.verifyMessage(senderPubKey, sigPayload, session.sigR, session.sigS);
                        log(`[${srv.name}] ECDSA verify: ${verified ? 'VALID' : 'INVALID'} signature (age: ${Math.round(age / 1000)}s)`);
                        if (verified) {
                            const now = Date.now();
                            seenSignatures.set(sigFingerprint, now);
                            // Prune expired entries to prevent memory growth
                            for (const [fp, ts] of seenSignatures) {
                                if (now - ts > REPLAY_MAX_AGE) seenSignatures.delete(fp);
                            }
                            persistReplayGuard();
                        }
                    }
                } catch (e) {
                    log(`[${srv.name}] ECDSA verify error: ${e.message}`);
                }
            } else {
                log(`[${srv.name}] No signature attached, dropping message`);
                delete pendingRecvSessions[sessionId];
                return;
            }

            // Drop unverified messages silently
            if (!verified) {
                log(`[${srv.name}] Signature verification failed, dropping message`);
                delete pendingRecvSessions[sessionId];
                return;
            }

            // Decrypt: try ephemeral keys first (if negotiated), fallback to identity keys.
            // The sender may have used either set depending on their ephemeral state.
            let text, decryptedMPoint;
            const keySets = [getActiveKeys(session.senderHex)];
            if (ephemeralKeys[session.senderHex]?.state === 'complete') {
                keySets.push({ myPriv: dhPrivateKey.value, peerPub: senderPubKey });
            }
            for (const { myPriv, peerPub } of keySets) {
                try {
                    const dh = new DiffieHellman(myPriv, CURVE_NAME);
                    const shared = dh.computeSharedSecret(peerPub);
                    const scalar = await deriveScalar(shared.x, session.timestampMs, myPubKeyHex.value, session.j);
                    const invScalar = modInverse(scalar, curve.n);
                    const mPoint = ePoint.mul(invScalar);
                    const paddedText = koblitz.decode(mPoint, session.j);
                    text = paddedText.length > NONCE_LEN ? paddedText.substring(NONCE_LEN) : paddedText;
                    decryptedMPoint = mPoint;
                    log(`[${srv.name}] DH + HKDF(ts:dest:j) → scalar (${scalar.toString(16).substring(0, 16)}...)`);
                    log(`[${srv.name}] DH decrypt: M = E * scalar⁻¹ (M.x: ${mPoint.x.toString(16).substring(0, 16)}...)`);
                    log(`[${srv.name}] Koblitz decode: stripped nonce → "${text.substring(0, 30)}${text.length > 30 ? '...' : ''}" (j=${session.j})`);
                    break;
                } catch (_e) { continue; }
            }
            if (!text) {
                log(`[${srv.name}] Decryption failed with all keys`);
                delete pendingRecvSessions[sessionId];
                return;
            }

            // Re-encrypt M with identity keys for at-rest storage.
            // Transit may use ephemeral keys, but stored e_x must always be identity-encrypted
            // so loadMessages() can re-derive text after any number of rekey cycles.
            const identDh = new DiffieHellman(dhPrivateKey.value, CURVE_NAME);
            const identShared = identDh.computeSharedSecret(senderPubKey);
            const storageScalar = await deriveScalar(identShared.x, session.timestampMs, myPubKeyHex.value, session.j);
            const storageE = decryptedMPoint.mul(storageScalar);
            const [storageEX, storageEParity] = storageE.compress();

            // Check for ephemeral key exchange message
            if (text.charAt(0) === EPHEMERAL_MARKER) {
                await handleEphemeralMessage(text, session.senderHex);
                delete pendingRecvSessions[sessionId];
                return;
            }

            // Check for multipart header: \x01 + 8-char groupId + 3-char partIdx(padded base36) + 3-char total(padded base36)
            if (text.length >= MULTIPART_HEADER_LEN && text.charAt(0) === MULTIPART_MARKER) {
                const groupId = text.substring(1, 9);
                const partIdx = parseInt(text.substring(9, 12), 36);
                const total = parseInt(text.substring(12, 15), 36);
                if (!isNaN(partIdx) && !isNaN(total) && total > 1 && partIdx < total) {
                    const content = text.substring(MULTIPART_HEADER_LEN);
                    const key = session.senderHex + ':' + groupId;

                    if (!pendingMultiparts[key]) {
                        ensureContact(session.senderHex);
                        if (!messages[session.senderHex]) messages[session.senderHex] = [];
                        const placeholderIdx = messages[session.senderHex].length;
                        messages[session.senderHex].push({
                            text: `Receiving 1/${total}...`, sent: false,
                            time: new Date().toLocaleTimeString(), ts: Date.now(),
                            verified: true, _receiving: true,
                        });
                        scrollMessages();
                        pendingMultiparts[key] = {
                            total, parts: {}, verified: true,
                            senderHex: session.senderHex,
                            time: new Date().toLocaleTimeString(), ts: Date.now(),
                            msgIndex: placeholderIdx,
                        };
                    }
                    const mp = pendingMultiparts[key];
                    mp.parts[partIdx] = content;
                    if (!verified) mp.verified = false;

                    // Update placeholder with progress
                    const received = Object.keys(mp.parts).length;
                    if (messages[mp.senderHex] && messages[mp.senderHex][mp.msgIndex]) {
                        messages[mp.senderHex][mp.msgIndex].text = `Receiving ${received}/${total}...`;
                    }

                    // Reset timeout for incomplete multiparts
                    if (mp.timer) clearTimeout(mp.timer);
                    mp.timer = setTimeout(() => flushMultipart(key, true), 300000);

                    log(`[${srv.name}] Multipart chunk ${partIdx + 1}/${total} (group: ${groupId}) from ${session.senderHex.substring(0, 16)}...`);

                    // All parts received — assemble
                    if (Object.keys(mp.parts).length >= mp.total) {
                        flushMultipart(key, false);
                    }

                    delete pendingRecvSessions[sessionId];
                    return;
                }
            }

            ensureContact(session.senderHex);

            if (!messages[session.senderHex]) messages[session.senderHex] = [];
            messages[session.senderHex].push({
                text, sent: false, time: new Date().toLocaleTimeString(), ts: Date.now(),
                sigTs: session.timestampMs, // original sender timestamp for HKDF re-derivation
                verified, nonce: true,
                e_x: storageEX.toString(16), e_parity: Number(storageEParity), j: session.j,
            });
            saveMessages(session.senderHex);

            const viewing = activeContact.value && activeContact.value.keyHex === session.senderHex && view.value === 'chat';
            if (!viewing) unreadMessages[session.senderHex] = (unreadMessages[session.senderHex] || 0) + 1;

            delete pendingRecvSessions[sessionId];
            const c = contacts.find(c => c.keyHex === session.senderHex);
            const senderName = c ? c.nickname : session.senderHex.substring(0, 16) + '...';
            log(`[${srv.name}] Message received from ${senderName} (j=${session.j}, ${text.length} chars, verified): "${text.substring(0, 50)}${text.length > 50 ? '...' : ''}"`);
            notifyNewMessage(senderName, text);
            scrollMessages();
        }

        const SENT_MAP_TTL = 365 * 24 * 60 * 60 * 1000; // 1 year

        /** Remove stale entries from sentMessageMap to prevent unbounded memory growth. */
        function cleanSentMessageMap() {
            const now = Date.now();
            for (const sid of Object.keys(sentMessageMap)) {
                const entry = sentMessageMap[sid];
                if (entry.ts && now - entry.ts > SENT_MAP_TTL) {
                    delete sentMessageMap[sid];
                }
            }
        }

        /** Update message delivery status (sent/delivered/queued) from server acknowledgement. */
        function handleMsgStatus(payload, newStatus) {
            const sid = P.unpackSessionId(payload);
            const info = sentMessageMap[sid];
            if (!info) return;
            const msgList = messages[info.destHex];
            const c = contacts.find(c => c.keyHex === info.destHex);
            const dest = c ? c.nickname : info.destHex.substring(0, 16) + '...';
            const msg = msgList && msgList[info.msgIndex];
            if (msg) {
                if (msg._multipartTotal) {
                    msg._multipartDone = (msg._multipartDone || 0) + 1;
                    if (msg._multipartDone >= msg._multipartTotal) {
                        msg.status = newStatus;
                        msg._multipartDone = 0; // reset for next status level
                    }
                } else {
                    msg.status = newStatus;
                }
                saveMessages(info.destHex);
                log(`Message to ${dest} → ${newStatus}${msg._multipartTotal ? ` (${msg._multipartDone}/${msg._multipartTotal})` : ''}`);
            }
            delete sentMessageMap[sid];
            cleanSentMessageMap();
        }

        // === SEND MESSAGE ===
        //
        // Text is Koblitz-encoded into a curve point. secp521r1 supports ~55 chars per point,
        // minus 4-char nonce prefix = 51 usable chars per chunk (KOBLITZ_MAX).
        // Messages > 51 chars are split into multipart chunks with a 15-byte header:
        //   \x01 + groupId(8) + partIdx(3, base36) + total(3, base36) + payload(36 chars max)
        //
        const NONCE_LEN = 4;
        const KOBLITZ_MAX = 51;
        const MULTIPART_MARKER = '\x01';
        const MULTIPART_HEADER_LEN = 15;
        const MULTIPART_KOBLITZ_MAX = KOBLITZ_MAX - MULTIPART_HEADER_LEN; // 36 chars per chunk
        const MAX_MULTIPART_PARTS = 46656; // 36^3
        const MAX_MESSAGE_LENGTH = 36 * MULTIPART_KOBLITZ_MAX; // 1296 chars for text input
        const MAX_MEDIA_LENGTH = MAX_MULTIPART_PARTS * MULTIPART_KOBLITZ_MAX; // ~1.9M chars for media
        const maxMessageLength = ref(MAX_MESSAGE_LENGTH);

        // --- Ephemeral DH key exchange (forward secrecy) ---
        //
        // Protocol: in-band key exchange via \x02 marker over existing MO 3-pass.
        // Payload format: \x02 + type('I'|'R') + pubX_hex(132 chars padded) + ':' + parity(1 char)
        // Total ~136 chars → sent as multipart (4 chunks of 36 chars).
        //
        // Flow:
        //   1. PEER_ONLINE → initiator sends \x02I + ephemeral pub key
        //   2. Responder receives, generates own ephemeral, sends \x02R + pub key
        //   3. Both compute DH(myEphPriv, peerEphPub) → ephemeral shared secret
        //   4. Subsequent messages use ephemeral keys for transit encryption
        //
        // Key exchange messages are encrypted with identity keys (ephemeral doesn't exist yet).
        // Tiebreaker for simultaneous initiation: lower keyHex is canonical initiator.
        // Renegotiation: every REKEY_INTERVAL_MS when both peers are online.
        //
        const EPHEMERAL_MARKER = '\x02';
        const EPHEMERAL_INITIATE = 'I';
        const EPHEMERAL_RESPOND = 'R';
        const REKEY_INTERVAL_MS = 30 * 60 * 1000; // 30 min

        /** Return {myPriv, peerPub} for DH — ephemeral if negotiated, else identity keys. */
        function getActiveKeys(contactHex) {
            const ek = ephemeralKeys[contactHex];
            if (ek && ek.state === 'complete' && ek.peerPubX && ek.myPriv) {
                const peerPub = Point.decompress(ek.peerPubX, ek.peerPubParity, curve);
                return { myPriv: ek.myPriv, peerPub };
            }
            const destPt = hexToPoint(contactHex);
            return { myPriv: dhPrivateKey.value, peerPub: Point.decompress(destPt.x, destPt.parity, curve) };
        }

        /** Send a chunk silently (no UI message, no sentMessageMap tracking).
         *  Always uses identity keys for DH — used exclusively for key exchange payloads. */
        function sendInternalChunk(chunkText, destHex, srvIdx) {
            return new Promise(async (resolve) => {
                const srv = servers[srvIdx];
                while (srv._rateLimited) {
                    await new Promise(r => setTimeout(r, 500));
                }
                const nonce = generateNonce();
                const paddedText = nonce + chunkText;
                const [mPoint, j] = koblitz.encode(paddedText);
                const destPt = hexToPoint(destHex);
                const destPubKey = Point.decompress(destPt.x, destPt.parity, curve);
                const timestampMs = Date.now();
                // Always use identity keys for key exchange messages
                const dh = new DiffieHellman(dhPrivateKey.value, CURVE_NAME);
                const shared = dh.computeSharedSecret(destPubKey);
                const scalar = await deriveScalar(shared.x, timestampMs, destHex, j);
                const ePoint = mPoint.mul(scalar);
                const [_eX, eParity] = ePoint.compress();
                const sigPayload = `${ePoint.x.toString(16)}:${eParity}:${j}:${timestampMs}:${destHex}`;
                const signer = new DigitalSignature(dhPrivateKey.value, CURVE_NAME);
                const [sigR, sigS] = await signer.signMessage(sigPayload);
                const c1Point = srv.mo.encrypt(ePoint);
                const [c1X, c1Parity] = c1Point.compress();
                if (!pendingSendQueues[srvIdx]) pendingSendQueues[srvIdx] = [];
                pendingSendQueues[srvIdx].push({ moInstance: srv.mo, destHex, j, msgIndex: -1, srvIdx, _resolve: resolve });
                srv.ws.send(P.packMoSendInit(destPt.x, destPt.parity, j, c1X, c1Parity, sigR, sigS, timestampMs));
            });
        }

        /** Send an ephemeral key exchange payload via multipart (silent, no UI).
         *  Splits payload into multipart chunks if it exceeds KOBLITZ_MAX. */
        async function sendEphemeralPayload(payload, destHex, srvIdx) {
            if (payload.length <= KOBLITZ_MAX) {
                await enqueueSend(() => sendInternalChunk(payload, destHex, srvIdx));
            } else {
                const groupId = generateGroupId();
                const parts = splitMedia(payload, MULTIPART_KOBLITZ_MAX);
                const total = parts.length;
                for (let i = 0; i < total; i++) {
                    const header = MULTIPART_MARKER + groupId + i.toString(36).padStart(3, '0') + total.toString(36).padStart(3, '0');
                    await enqueueSend(() => sendInternalChunk(header + parts[i], destHex, srvIdx));
                }
            }
        }

        /** Initiate ephemeral key exchange with a contact.
         *  Generates a new ephemeral key pair, sends \x02I + pub to the peer.
         *  Skips if exchange is already in progress or completed within REKEY_INTERVAL_MS. */
        async function initiateEphemeralExchange(contactHex, srvIdx) {
            const ek = ephemeralKeys[contactHex];
            if (ek && ek.state === 'initiated') return;
            if (ek && ek.state === 'complete' && ek.negotiatedAt && Date.now() - ek.negotiatedAt < REKEY_INTERVAL_MS) return;

            const priv = randomPrivateKey();
            const dh = new DiffieHellman(priv, CURVE_NAME);
            const [pubX, pubParity] = dh.publicKey.compress();
            const gen = (ek && ek.generation) ? ek.generation + 1 : 1;

            ephemeralKeys[contactHex] = {
                myPriv: priv,
                myPubX: pubX,
                myPubParity: pubParity,
                peerPubX: null,
                peerPubParity: null,
                state: 'initiated',
                negotiatedAt: 0,
                generation: gen,
            };

            const payload = EPHEMERAL_MARKER + EPHEMERAL_INITIATE + pubX.toString(16).padStart(132, '0') + ':' + pubParity.toString();
            log(`Initiating ephemeral key exchange with ${contactHex.substring(0, 16)}... (gen ${gen})`);
            await sendEphemeralPayload(payload, contactHex, srvIdx);
            saveEphemeralKeys();
        }

        /** Handle an incoming ephemeral key exchange message (\x02I or \x02R).
         *  On 'I' (initiate): store peer's pub, generate own ephemeral, respond with \x02R, state → complete.
         *  On 'R' (respond): store peer's pub, state → complete. Both sides now share ephemeral DH secret. */
        async function handleEphemeralMessage(text, senderHex) {
            const type = text.charAt(1);
            const body = text.substring(2);
            const colonIdx = body.lastIndexOf(':');
            if (colonIdx < 0) { log('Malformed ephemeral message'); return; }
            const peerPubX = BigInt('0x' + body.substring(0, colonIdx));
            const peerPubParity = BigInt(body.substring(colonIdx + 1));

            if (type === EPHEMERAL_INITIATE) {
                const ek = ephemeralKeys[senderHex];
                // Tiebreaker for simultaneous initiation: lower keyHex is canonical initiator
                if (ek && ek.state === 'initiated') {
                    if (myPubKeyHex.value < senderHex) {
                        log(`Ephemeral tiebreaker: I am canonical initiator, ignoring peer's initiate`);
                        return;
                    }
                    // Peer wins — abandon my initiation, respond to theirs
                }

                const priv = randomPrivateKey();
                const dh = new DiffieHellman(priv, CURVE_NAME);
                const [pubX, pubParity] = dh.publicKey.compress();
                const gen = (ek && ek.generation) ? ek.generation + 1 : 1;

                ephemeralKeys[senderHex] = {
                    myPriv: priv,
                    myPubX: pubX,
                    myPubParity: pubParity,
                    peerPubX: peerPubX,
                    peerPubParity: peerPubParity,
                    state: 'complete',
                    negotiatedAt: Date.now(),
                    generation: gen,
                };

                const payload = EPHEMERAL_MARKER + EPHEMERAL_RESPOND + pubX.toString(16).padStart(132, '0') + ':' + pubParity.toString();
                const srvIdx = findServerForPeer(senderHex);
                if (srvIdx >= 0) {
                    log(`Responding to ephemeral key exchange from ${senderHex.substring(0, 16)}... (gen ${gen})`);
                    await sendEphemeralPayload(payload, senderHex, srvIdx);
                }
                saveEphemeralKeys();
                log(`Ephemeral key exchange complete with ${senderHex.substring(0, 16)}... (gen ${gen})`);
            } else if (type === EPHEMERAL_RESPOND) {
                const ek = ephemeralKeys[senderHex];
                if (!ek || ek.state !== 'initiated') {
                    log(`Unexpected ephemeral response from ${senderHex.substring(0, 16)}...`);
                    return;
                }
                ek.peerPubX = peerPubX;
                ek.peerPubParity = peerPubParity;
                ek.state = 'complete';
                ek.negotiatedAt = Date.now();
                saveEphemeralKeys();
                log(`Ephemeral key exchange complete with ${senderHex.substring(0, 16)}... (gen ${ek.generation})`);
            }
        }

        /** Persist ephemeral keys to IndexedDB.
         *  Private keys are encrypted with AES-GCM (_ephemeralAesKey derived from user password).
         *  Public keys and metadata are stored in plaintext (not secrets). */
        async function saveEphemeralKeys() {
            if (!_ephemeralAesKey) return;
            try {
                const data = {};
                for (const [hex, ek] of Object.entries(ephemeralKeys)) {
                    const privEnc = await aesGcmEncrypt(_ephemeralAesKey, bigintToFixedBytes(ek.myPriv));
                    data[hex] = {
                        myPriv_iv: privEnc.iv, myPriv_ct: privEnc.ciphertext,
                        myPubX: ek.myPubX.toString(16),
                        myPubParity: ek.myPubParity.toString(),
                        peerPubX: ek.peerPubX ? ek.peerPubX.toString(16) : null,
                        peerPubParity: ek.peerPubParity !== null && ek.peerPubParity !== undefined ? ek.peerPubParity.toString() : null,
                        state: ek.state,
                        negotiatedAt: ek.negotiatedAt,
                        generation: ek.generation,
                    };
                }
                await idbPut('keys', 'ephemeral', { contacts: data });
            } catch (e) {
                log('Failed to save ephemeral keys: ' + e.message);
            }
        }

        /** Load and decrypt ephemeral keys from IndexedDB. Called during restoreKeys(). */
        async function loadEphemeralKeys(aesKey) {
            try {
                const stored = await idbGet('keys', 'ephemeral');
                if (!stored || !stored.contacts) return;
                for (const [hex, d] of Object.entries(stored.contacts)) {
                    const privBytes = await aesGcmDecrypt(aesKey, d.myPriv_iv, d.myPriv_ct);
                    const myPriv = fixedBytesToBigint(privBytes);
                    ephemeralKeys[hex] = {
                        myPriv,
                        myPubX: BigInt('0x' + d.myPubX),
                        myPubParity: BigInt(d.myPubParity),
                        peerPubX: d.peerPubX ? BigInt('0x' + d.peerPubX) : null,
                        peerPubParity: d.peerPubParity !== null ? BigInt(d.peerPubParity) : null,
                        state: d.state,
                        negotiatedAt: d.negotiatedAt,
                        generation: d.generation,
                    };
                }
                const count = Object.keys(stored.contacts).length;
                if (count) log(`Ephemeral keys restored for ${count} contact(s)`);
            } catch (e) {
                log('Failed to load ephemeral keys: ' + e.message);
            }
        }

        // Send semaphore — ensures only one MO 3-pass is in-flight at a time.
        // Without this, concurrent sends would interleave MO steps and corrupt sessions.
        let sendQueueTail = Promise.resolve();
        function enqueueSend(fn) {
            sendQueueTail = sendQueueTail.then(fn, fn);
            return sendQueueTail;
        }

        /** Generate a random 8-char hex ID for multipart message grouping. */
        function generateGroupId() {
            const bytes = new Uint8Array(4);
            crypto.getRandomValues(bytes);
            return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
        }

        /** Split text into chunks <= max, breaking at spaces when possible. */
        function splitText(text, max) {
            max = max || KOBLITZ_MAX;
            const parts = [];
            let remaining = text;
            while (remaining.length > max) {
                let cut = remaining.lastIndexOf(' ', max);
                if (cut <= 0) cut = max; // no space found, hard cut
                parts.push(remaining.substring(0, cut));
                remaining = remaining.substring(cut).trimStart();
            }
            if (remaining.length) parts.push(remaining);
            return parts;
        }

        /** Strict split for binary/media data — exact character boundaries, no trimming. */
        function splitMedia(text, max) {
            const parts = [];
            for (let i = 0; i < text.length; i += max) {
                parts.push(text.substring(i, i + max));
            }
            return parts;
        }

        /** Encrypt and send a single text chunk via MO 3-pass.
         *  Uses ephemeral DH keys for transit if negotiated, identity keys otherwise.
         *  ECDSA signature always uses identity key (binds to permanent identity).
         *  At-rest storage (e_x) is always re-encrypted with identity keys so it
         *  survives ephemeral rekey cycles and can be re-derived on reload. */
        function sendChunk(chunkText, destHex, srvIdx, multipartMsgIndex) {
            return new Promise(async (resolve) => {
                const srv = servers[srvIdx];
                // Wait if server signaled rate limiting
                while (srv._rateLimited) {
                    await new Promise(r => setTimeout(r, 500));
                }
                // Prepend random nonce to make encryption non-deterministic
                const nonce = generateNonce();
                const paddedText = nonce + chunkText;
                const [mPoint, j] = koblitz.encode(paddedText);
                // Verify Koblitz round-trip integrity
                const roundTrip = koblitz.decode(mPoint, j);
                if (roundTrip !== paddedText) {
                    log(`KOBLITZ CORRUPTION: encode/decode mismatch! expected ${paddedText.length} chars, got ${roundTrip.length} chars`);
                    log(`  First diff at char ${[...paddedText].findIndex((c, i) => c !== roundTrip[i])}`);
                }
                log(`Koblitz encode: nonce="${nonce}" + "${chunkText.substring(0, 26)}${chunkText.length > 26 ? '...' : ''}" → point (j=${j})`);
                const destPt = hexToPoint(destHex);
                const timestampMs = Date.now();
                // Use ephemeral keys if negotiated, else identity keys
                const { myPriv, peerPub } = getActiveKeys(destHex);
                const dh = new DiffieHellman(myPriv, CURVE_NAME);
                const shared = dh.computeSharedSecret(peerPub);
                const scalar = await deriveScalar(shared.x, timestampMs, destHex, j);
                log(`DH + HKDF(ts:dest:j) → scalar (${scalar.toString(16).substring(0, 16)}...)`);
                const ePoint = mPoint.mul(scalar);
                log(`DH encrypt: E = M * scalar (E.x: ${ePoint.x.toString(16).substring(0, 16)}...)`);

                // Compress E before signing so eParity is included in the payload
                const [eX, eParity] = ePoint.compress();

                // Sign E.x:eParity:j:timestamp:destHex for anti-replay and integrity (signMessage hashes internally)
                const sigPayload = `${ePoint.x.toString(16)}:${eParity}:${j}:${timestampMs}:${destHex}`;
                const signer = new DigitalSignature(dhPrivateKey.value, CURVE_NAME);
                const [sigR, sigS] = await signer.signMessage(sigPayload);
                log(`ECDSA sign: sig(E.x:eParity:j:ts:dest) = (r: ${sigR.toString(16).substring(0, 12)}..., s: ${sigS.toString(16).substring(0, 12)}...)`);

                // Re-encrypt M with identity keys for at-rest storage (survives ephemeral rekey)
                let storageEX = eX, storageEParity = eParity;
                if (myPriv !== dhPrivateKey.value) {
                    const destPubKey = Point.decompress(destPt.x, destPt.parity, curve);
                    const identDh = new DiffieHellman(dhPrivateKey.value, CURVE_NAME);
                    const identShared = identDh.computeSharedSecret(destPubKey);
                    const identScalar = await deriveScalar(identShared.x, timestampMs, destHex, j);
                    const identE = mPoint.mul(identScalar);
                    [storageEX, storageEParity] = identE.compress();
                }

                const c1Point = srv.mo.encrypt(ePoint);
                log(`MO encrypt: C1 = mo.encrypt(E) (C1.x: ${c1Point.x.toString(16).substring(0, 16)}...)`);
                const [c1X, c1Parity] = c1Point.compress();

                let msgIndex;
                if (multipartMsgIndex !== undefined) {
                    msgIndex = multipartMsgIndex;
                } else {
                    if (!messages[destHex]) messages[destHex] = [];
                    msgIndex = messages[destHex].length;
                    messages[destHex].push({ text: chunkText, sent: true, time: new Date().toLocaleTimeString(), ts: timestampMs, status: 'sending', e_x: storageEX.toString(16), e_parity: Number(storageEParity), j, nonce: true });
                    saveMessages(destHex);
                }

                if (!pendingSendQueues[srvIdx]) pendingSendQueues[srvIdx] = [];
                pendingSendQueues[srvIdx].push({ moInstance: srv.mo, destHex, j, msgIndex, srvIdx, _resolve: resolve });

                log(`[${srv.name}] >> MO_SEND_INIT to ${activeContact.value.nickname} (j=${j}, ${chunkText.length} chars, signed)`);
                srv.ws.send(P.packMoSendInit(destPt.x, destPt.parity, j, c1X, c1Parity, sigR, sigS, timestampMs));
            });
        }

        // === MEDIA HELPERS ===
        const fileInput = ref(null);

        function _isMediaMessage(text) { return text && text.startsWith('data:'); }
        function isImageMsg(text) { return text && text.startsWith('data:image/'); }
        function isAudioMsg(text) { return text && text.startsWith('data:audio/'); }
        function isVideoMsg(text) { return text && text.startsWith('data:video/'); }

        // Convert data URI to Blob URL for reliable media playback
        // Large data URIs in src attributes fail in many browsers
        const blobUrlCache = new Map();
        function dataUriToBlobUrl(dataUri) {
            const cacheKey = dataUri.length + ':' + dataUri.substring(0, 80);
            if (blobUrlCache.has(cacheKey)) return blobUrlCache.get(cacheKey);
            try {
                const commaIdx = dataUri.indexOf(',');
                if (commaIdx < 0) return dataUri;
                const header = dataUri.substring(0, commaIdx);
                const base64Data = dataUri.substring(commaIdx + 1);
                // Capture full MIME type with parameters (e.g. audio/webm;codecs=opus)
                const mimeMatch = header.match(/data:(.+);base64/);
                const mime = mimeMatch ? mimeMatch[1] : 'application/octet-stream';
                const binary = atob(base64Data);
                const bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                const blob = new Blob([bytes], { type: mime });
                const url = URL.createObjectURL(blob);
                blobUrlCache.set(cacheKey, url);
                return url;
            } catch (e) {
                log(`Blob URL conversion failed: ${e.message}`);
                return dataUri;
            }
        }

        // For images: auto-convert on render (small, fast)
        function mediaSrc(dataUri) {
            if (!dataUri || !dataUri.startsWith('data:')) return dataUri;
            return dataUriToBlobUrl(dataUri);
        }

        // For audio/video: lazy load — only convert when user clicks
        function loadMedia(msg) {
            if (msg._blobUrl) return;
            const url = dataUriToBlobUrl(msg.text);
            if (url && url.startsWith('blob:')) {
                msg._blobUrl = url;
            } else {
                // Blob conversion failed (corrupt data) — show error
                msg._blobUrl = 'error';
                log(`Media corrupted: could not decode base64 (${msg.text.length} chars)`);
            }
        }

        function triggerFileInput() {
            if (fileInput.value) fileInput.value.click();
        }

        function compressImage(file, maxWidth, quality) {
            return new Promise((resolve, reject) => {
                const img = new Image();
                img.onload = () => {
                    const scale = Math.min(1, maxWidth / img.width);
                    const w = Math.round(img.width * scale);
                    const h = Math.round(img.height * scale);
                    const canvas = document.createElement('canvas');
                    canvas.width = w;
                    canvas.height = h;
                    canvas.getContext('2d').drawImage(img, 0, 0, w, h);
                    resolve(canvas.toDataURL('image/jpeg', quality));
                };
                img.onerror = reject;
                img.src = URL.createObjectURL(file);
            });
        }

        function fileToDataUri(file) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = () => resolve(reader.result);
                reader.onerror = reject;
                reader.readAsDataURL(file);
            });
        }

        /** Send a media file (image/audio/video) as data URI via multipart chunks. */
        async function sendMediaMessage(dataUri, destHex, srvIdx) {
            const parts = splitMedia(dataUri, MULTIPART_KOBLITZ_MAX);
            if (parts.length > MAX_MULTIPART_PARTS) {
                log(`Media too large: ${parts.length} parts needed (max ${MAX_MULTIPART_PARTS})`);
                return;
            }
            const groupId = generateGroupId();
            const total = parts.length;
            log(`Media message: ${dataUri.length} chars, ${total} parts (group: ${groupId})`);

            if (!messages[destHex]) messages[destHex] = [];
            const msgIndex = messages[destHex].length;
            messages[destHex].push({
                text: dataUri, sent: true, time: new Date().toLocaleTimeString(),
                ts: Date.now(), status: 'sending',
                _multipartTotal: total, _multipartDone: 0,
            });
            saveMessages(destHex);
            scrollMessages();

            for (let i = 0; i < total; i++) {
                const header = MULTIPART_MARKER + groupId + i.toString(36).padStart(3, '0') + total.toString(36).padStart(3, '0');
                await enqueueSend(() => sendChunk(header + parts[i], destHex, srvIdx, msgIndex));
            }
        }

        async function handleFileSelect(event) {
            const file = event.target.files && event.target.files[0];
            if (!file) return;
            if (fileInput.value) fileInput.value.value = '';
            if (!activeContact.value) { log('No active contact selected'); return; }

            const destHex = activeContact.value.keyHex;
            const srvIdx = findServerForPeer(destHex);
            if (srvIdx < 0) { log('No connected server available'); return; }

            let dataUri;
            try {
                if (file.type.startsWith('image/')) {
                    dataUri = await compressImage(file, 150, 0.4);
                    log(`Image compressed: ${file.name} → ${dataUri.length} chars`);
                } else if (file.type.startsWith('video/') || file.type.startsWith('audio/')) {
                    dataUri = await fileToDataUri(file);
                    log(`Media file: ${file.name} → ${dataUri.length} chars`);
                } else {
                    log(`Unsupported file type: ${file.type}`);
                    return;
                }
            } catch (err) {
                log(`File read error: ${err.message}`);
                return;
            }

            if (dataUri.length > MAX_MEDIA_LENGTH) {
                log(`File too large: ${dataUri.length} chars (max ${MAX_MEDIA_LENGTH}). Try a smaller file.`);
                return;
            }

            sendMediaMessage(dataUri, destHex, srvIdx);
        }

        // === AUDIO RECORDING ===
        const isRecording = ref(false);
        let mediaRecorder = null;
        let recordedChunks = [];

        function toggleRecording() {
            if (!activeContact.value) { log('No active contact selected'); return; }
            if (isRecording.value) {
                // Stop recording
                if (mediaRecorder && mediaRecorder.state !== 'inactive') {
                    mediaRecorder.stop();
                }
                isRecording.value = false;
                return;
            }

            // Start recording
            navigator.mediaDevices.getUserMedia({ audio: true }).then((stream) => {
                recordedChunks = [];
                let options;
                try {
                    options = { mimeType: 'audio/webm;codecs=opus', audioBitsPerSecond: 8000 };
                    mediaRecorder = new MediaRecorder(stream, options);
                } catch (_e) {
                    options = { mimeType: 'audio/webm', audioBitsPerSecond: 8000 };
                    mediaRecorder = new MediaRecorder(stream, options);
                }

                mediaRecorder.ondataavailable = (e) => {
                    if (e.data.size > 0) recordedChunks.push(e.data);
                };

                mediaRecorder.onstop = () => {
                    stream.getTracks().forEach(t => t.stop());
                    const blob = new Blob(recordedChunks, { type: mediaRecorder.mimeType });
                    const reader = new FileReader();
                    reader.onload = () => {
                        const dataUri = reader.result;
                        if (dataUri.length > MAX_MEDIA_LENGTH) {
                            log(`Voice message too large: ${dataUri.length} chars (max ${MAX_MEDIA_LENGTH})`);
                            return;
                        }
                        const destHex = activeContact.value.keyHex;
                        const srvIdx = findServerForPeer(destHex);
                        if (srvIdx < 0) { log('No connected server available'); return; }
                        log(`Voice message: ${dataUri.length} chars`);
                        sendMediaMessage(dataUri, destHex, srvIdx);
                    };
                    reader.readAsDataURL(blob);
                };

                mediaRecorder.start();
                isRecording.value = true;
                log('Recording audio...');
            }).catch((err) => {
                log(`Microphone access denied: ${err.message}`);
            });
        }

        /** Send a text message to the active contact. Splits into multipart if > KOBLITZ_MAX chars. */
        async function sendMessage() {
            if (!messageInput.value.trim() || !activeContact.value) return;
            const text = messageInput.value.trim();
            const destHex = activeContact.value.keyHex;

            const srvIdx = findServerForPeer(destHex);
            if (srvIdx < 0) { log('No connected server available'); return; }

            messageInput.value = '';
            scrollMessages();

            if (text.length <= KOBLITZ_MAX) {
                await enqueueSend(() => sendChunk(text, destHex, srvIdx));
            } else {
                const groupId = generateGroupId();
                const parts = splitText(text, MULTIPART_KOBLITZ_MAX);
                const total = parts.length;
                log(`Message split into ${total} parts (group: ${groupId})`);

                // Push ONE message with full text for display
                if (!messages[destHex]) messages[destHex] = [];
                const msgIndex = messages[destHex].length;
                messages[destHex].push({
                    text, sent: true, time: new Date().toLocaleTimeString(),
                    ts: Date.now(), status: 'sending',
                    _multipartTotal: total, _multipartDone: 0,
                });
                saveMessages(destHex);

                for (let i = 0; i < total; i++) {
                    const header = MULTIPART_MARKER + groupId + i.toString(36).padStart(3, '0') + total.toString(36).padStart(3, '0');
                    await enqueueSend(() => sendChunk(header + parts[i], destHex, srvIdx, msgIndex));
                }
            }
        }

        // === SERVER MANAGEMENT ===
        function addServer() {
            const name = newServerName.value.trim();
            let url = newServerUrl.value.trim();
            if (!name || !url) return;
            if (!url.startsWith('ws://') && !url.startsWith('wss://')) {
                url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + url;
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
            const s = servers[index];
            if (!s) return;
            disconnectServer(index);
            log(`Server removed: ${s.name}`);
            servers.splice(index, 1);
            saveServers();
        }

        // === CONTACT MANAGEMENT ===
        function addContact() {
            const nick = newContactNick.value.trim();
            const key = newContactKey.value.trim();
            if (!nick || !key || !key.includes(':')) { log('Invalid contact'); return; }
            // Validate that the key is a valid point on the curve
            try {
                const pt = hexToPoint(key);
                Point.decompress(pt.x, pt.parity, curve);
            } catch (e) {
                log(`Invalid public key: ${e.message}`);
                return;
            }
            if (contacts.find(c => c.keyHex === key)) { log('Contact already exists'); return; }
            contacts.push({ nickname: nick, keyHex: key });
            saveContacts();
            newContactNick.value = '';
            newContactKey.value = '';
            log(`Contact added: ${nick}`);
        }

        function removeContact(index) {
            const c = contacts[index];
            // Purge all message history for this contact
            delete messages[c.keyHex];
            idbDel('messages', c.keyHex).catch(() => {});
            // Clean up ephemeral keys for this contact
            delete ephemeralKeys[c.keyHex];
            saveEphemeralKeys();
            // Remove any pending multiparts from this contact
            for (const key of Object.keys(pendingMultiparts)) {
                if (key.startsWith(c.keyHex + ':')) delete pendingMultiparts[key];
            }
            log(`Contact removed: ${c.nickname} (messages purged)`);
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

        /** Auto-add unknown senders to the contact list so messages are not lost. */
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
            messageInput, maxMessageLength, messagesEl, logEl, fileInput,
            handleFileSelect, triggerFileInput, isImageMsg, isAudioMsg, isVideoMsg, mediaSrc, loadMedia,
            isRecording, toggleRecording,
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
            exportKeys, importKeys, triggerImport, importFileInput,
        };
    },
}).mount('#app');
