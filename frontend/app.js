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

/** Modular inverse via extended Euclidean algorithm. */
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

// --- Key derivation and encryption ---

/** SHA-256(password) -> Koblitz.encode(hash_hex) -> point.x */
async function deriveKeyFromPassword(password) {
    const data = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashHex = Array.from(new Uint8Array(hashBuffer), b => b.toString(16).padStart(2, '0')).join('');
    const kob = new Koblitz(CURVE_NAME);
    const [point] = kob.encode(hashHex);
    return point.x;
}

/** SHA-256 fingerprint of derived key for password verification. */
async function hashCheck(dk) {
    const data = new TextEncoder().encode(dk.toString(16));
    const buf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
}

/** (key + derived) mod n */
function encryptKey(privateKey, derivedKey) {
    return ((privateKey + derivedKey) % curve.n).toString(16);
}

/** (encrypted - derived) mod n */
function decryptKey(encryptedHex, derivedKey) {
    const encrypted = BigInt('0x' + encryptedHex);
    return ((encrypted - derivedKey) % curve.n + curve.n) % curve.n;
}

// --- IndexedDB storage ---

const DB_NAME = 'e2hat';
const DB_VERSION = 1;
let _db = null;

function openDB() {
    if (_db) return Promise.resolve(_db);
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = (e) => {
            const db = e.target.result;
            for (const name of ['config', 'keys', 'messages']) {
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

        const pendingSendSessions = reactive({});
        const pendingSendQueues = {};  // srvIdx -> FIFO of sessions awaiting server-assigned ID
        const pendingRecvSessions = reactive({});
        const sentMessageMap = reactive({});
        const retryQueues = {};

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

        function saveMessages(contactHex) {
            if (contactHex) {
                const list = (messages[contactHex] || []).map(({ text, ...rest }) => rest);
                idbPut('messages', contactHex, list);
            } else {
                for (const key of Object.keys(messages)) {
                    const list = messages[key].map(({ text, ...rest }) => rest);
                    idbPut('messages', key, list);
                }
            }
        }

        const MSG_TTL = 365 * 24 * 60 * 60 * 1000; // 1 year in ms

        async function loadMessages() {
            const keys = await idbGetAllKeys('messages');
            if (!keys.length) return;
            const now = Date.now();
            const invCache = {};
            let totalLoaded = 0;
            let totalExpired = 0;
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
                messages[contactHex] = fresh.map(m => {
                    if (!m.e_x) return { ...m, text: '[unreadable]' };
                    try {
                        if (!invCache[contactHex]) {
                            const pt = hexToPoint(contactHex);
                            const pubKey = Point.decompress(pt.x, pt.parity, curve);
                            const dh = new DiffieHellman(dhPrivateKey.value, CURVE_NAME);
                            const shared = dh.computeSharedSecret(pubKey);
                            invCache[contactHex] = modInverse(shared.x, curve.n);
                        }
                        const ePoint = Point.decompress(BigInt('0x' + m.e_x), BigInt(m.e_parity), curve);
                        const mPoint = ePoint.mul(invCache[contactHex]);
                        return { ...m, text: koblitz.decode(mPoint, m.j) };
                    } catch {
                        return { ...m, text: '[decrypt error]' };
                    }
                });
                totalLoaded += messages[contactHex].length;
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

        function saveKeys() {
            if (!savePassword.value.trim() || !dhPrivateKey.value || !moPrivateKey.value) return;
            status.value = 'Encrypting keys...';
            setTimeout(async () => {
                try {
                    const dk = await deriveKeyFromPassword(savePassword.value);
                    const check = await hashCheck(dk);
                    await idbPut('keys', 'encrypted', {
                        dh: encryptKey(dhPrivateKey.value, dk),
                        mo: encryptKey(moPrivateKey.value, dk),
                        check,
                    });
                    await idbPut('config', 'nickname', nickname.value);
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
            setTimeout(async () => {
                try {
                    const data = await idbGet('keys', 'encrypted');
                    if (!data) { status.value = 'No saved keys'; return; }
                    const dk = await deriveKeyFromPassword(restorePassword.value);
                    const check = await hashCheck(dk);
                    if (data.check && data.check !== check) {
                        status.value = 'Wrong password';
                        return;
                    }
                    const dhKey = decryptKey(data.dh, dk);
                    const moKey = decryptKey(data.mo, dk);
                    const dh = new DiffieHellman(dhKey, CURVE_NAME);
                    dhPrivateKey.value = dhKey;
                    dhPublicKey.value = dh.publicKey;
                    moPrivateKey.value = moKey;
    
                    const [x, parity] = dhPublicKey.value.compress();
                    myPubKeyHex.value = pointToHex(x, parity);
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
        }

        // === SERVER CONNECTION ===
        // Use a Web Worker for timers so they fire even when the tab is in background.
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
            if (srv._manualDisconnect) return;
            const delay = Math.min(30000, 2000 * Math.pow(2, srv._retries || 0));
            srv._retries = (srv._retries || 0) + 1;
            log(`[${srv.name}] Reconnecting in ${Math.round(delay / 1000)}s...`);
            reconnectTimers[index] = true;
            timerWorker.postMessage({ action: 'start', id: index, delay });
        }

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
            srv._manualDisconnect = true;
            if (reconnectTimers[index]) { timerWorker.postMessage({ action: 'cancel', id: index }); delete reconnectTimers[index]; }
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
                    const wInfo = P.unpackWelcome(payload);
                    srv.state = 'connected';
                    log(`[${srv.name}] Handshake complete (MO pub ${wInfo.x.toString(16).substring(0, 12)}...)`);
                    // Retry 'sending' messages on this server
                    const retryItems = [];
                    for (const destHex of Object.keys(messages)) {
                        const msgList = messages[destHex];
                        for (let i = 0; i < msgList.length; i++) {
                            const m = msgList[i];
                            if (m.status === 'sending' && m.e_x) {
                                retryItems.push({ destHex, msgIndex: i, e_x: m.e_x, e_parity: m.e_parity, j: m.j });
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
                    const names = { [P.ERR_USER_NOT_FOUND]: 'User not found', [P.ERR_INVALID_FRAME]: 'Invalid frame', [P.ERR_SESSION_EXPIRED]: 'Session expired' };
                    log(`[${srv.name}] ERROR: ${names[code] || code}`);
                    break;
                }
                case P.PEER_ONLINE: {
                    const { x, parity } = P.unpackPeerEvent(payload);
                    const hex = pointToHex(x, parity);
                    srv.onlinePeers.add(hex);
                    const c = contacts.find(c => c.keyHex === hex);
                    log(`[${srv.name}] Peer online: ${c ? c.nickname : hex.substring(0, 16) + '...'} (${srv.onlinePeers.size} peers)`);
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
            delete pendingSendSessions[sessionId];
            if (retrySrvIdx !== undefined) flushNextRetry(retrySrvIdx);
        }

        /** Drain one retry from the queue; next fires after step2 completes. */
        function flushNextRetry(srvIdx) {
            const queue = retryQueues[srvIdx];
            if (!queue || !queue.length) return;
            const srv = servers[srvIdx];
            if (!srv || srv.state !== 'connected' || !srv.ws) return;

            const item = queue.shift();
            const destPt = hexToPoint(item.destHex);
            const ePoint = Point.decompress(BigInt('0x' + item.e_x), BigInt(item.e_parity), curve);
            const c1Point = srv.mo.encrypt(ePoint);
            const [c1X, c1Parity] = c1Point.compress();

            if (!pendingSendQueues[srvIdx]) pendingSendQueues[srvIdx] = [];
            pendingSendQueues[srvIdx].push({
                moInstance: srv.mo, destHex: item.destHex, j: item.j,
                msgIndex: item.msgIndex, srvIdx,
            });

            const retryDest = contacts.find(c => c.keyHex === item.destHex);
            log(`[${srv.name}] >> MO_SEND_INIT (retry to ${retryDest ? retryDest.nickname : item.destHex.substring(0, 16) + '...'}, j=${item.j})`);
            srv.ws.send(P.packMoSendInit(destPt.x, destPt.parity, item.j, c1X, c1Parity));
        }

        /** MO recv step 1: add our MO layer -> C2' = mo.encrypt(C1'), send back. */
        function handleMoRecvInit(srvIdx, payload) {
            const srv = servers[srvIdx];
            const { sessionId, senderX, senderParity, j, c1X, c1Parity } = P.unpackMoRecvInit(payload);
            const senderHex = pointToHex(senderX, senderParity);

            const c1Point = Point.decompress(c1X, c1Parity, curve);
            const recvSender = contacts.find(c => c.keyHex === senderHex);
            log(`[${srv.name}] MO received C1' from server (C1'.x: ${c1Point.x.toString(16).substring(0, 16)}..., from ${recvSender ? recvSender.nickname : senderHex.substring(0, 16) + '...'})`);
            const c2Point = srv.mo.encrypt(c1Point);
            log(`[${srv.name}] MO encrypt: C2' = mo.encrypt(C1') (C2'.x: ${c2Point.x.toString(16).substring(0, 16)}...)`);
            const [c2X, c2Parity] = c2Point.compress();

            pendingRecvSessions[sessionId] = { serverIndex: srvIdx, moInstance: srv.mo, senderHex, j };

            log(`[${srv.name}] >> MO_RECV_STEP2 (sid=${sessionId})`);
            srv.ws.send(P.packMoRecvStep2(sessionId, c2X, c2Parity));
        }

        /** MO recv step 3: strip MO -> E, then DH decrypt -> M, Koblitz decode -> text. */
        function handleMoRecvStep3(srvIdx, payload) {
            const srv = servers[srvIdx];
            const { sessionId, x, parity } = P.unpackMoRecvStep3(payload);

            const session = pendingRecvSessions[sessionId];
            if (!session) { log(`  Session ${sessionId} not found`); return; }

            const c3Point = Point.decompress(x, parity, curve);
            const ePoint = session.moInstance.decrypt(c3Point);
            log(`[${srv.name}] MO decrypt: E = mo.decrypt(C3') (E.x: ${ePoint.x.toString(16).substring(0, 16)}...)`);
            const [recvEX, recvEParity] = ePoint.compress();

            const senderPt = hexToPoint(session.senderHex);
            const senderPubKey = Point.decompress(senderPt.x, senderPt.parity, curve);
            const dh = new DiffieHellman(dhPrivateKey.value, CURVE_NAME);
            const shared = dh.computeSharedSecret(senderPubKey);
            log(`[${srv.name}] DH shared secret computed (x: ${shared.x.toString(16).substring(0, 16)}...)`);
            const invX = modInverse(shared.x, curve.n);
            const mPoint = ePoint.mul(invX);
            log(`[${srv.name}] DH decrypt: M = E * shared.x⁻¹ (M.x: ${mPoint.x.toString(16).substring(0, 16)}...)`);
            const text = koblitz.decode(mPoint, session.j);
            log(`[${srv.name}] Koblitz decode: point → "${text.substring(0, 30)}${text.length > 30 ? '...' : ''}" (j=${session.j})`);

            ensureContact(session.senderHex);

            if (!messages[session.senderHex]) messages[session.senderHex] = [];
            messages[session.senderHex].push({
                text, sent: false, time: new Date().toLocaleTimeString(), ts: Date.now(),
                e_x: recvEX.toString(16), e_parity: Number(recvEParity), j: session.j,
            });
            saveMessages(session.senderHex);

            const viewing = activeContact.value && activeContact.value.keyHex === session.senderHex && view.value === 'chat';
            if (!viewing) unreadMessages[session.senderHex] = (unreadMessages[session.senderHex] || 0) + 1;

            delete pendingRecvSessions[sessionId];
            const c = contacts.find(c => c.keyHex === session.senderHex);
            const senderName = c ? c.nickname : session.senderHex.substring(0, 16) + '...';
            log(`[${srv.name}] Message received from ${senderName} (j=${session.j}, ${text.length} chars): "${text.substring(0, 50)}${text.length > 50 ? '...' : ''}"`);
            notifyNewMessage(senderName, text);
            scrollMessages();
        }

        const SENT_MAP_TTL = 365 * 24 * 60 * 60 * 1000; // 1 year in ms

        function cleanSentMessageMap() {
            const now = Date.now();
            for (const sid of Object.keys(sentMessageMap)) {
                const entry = sentMessageMap[sid];
                if (entry.ts && now - entry.ts > SENT_MAP_TTL) {
                    delete sentMessageMap[sid];
                }
            }
        }

        function handleMsgStatus(payload, newStatus) {
            const sid = P.unpackSessionId(payload);
            const info = sentMessageMap[sid];
            if (!info) return;
            const msgList = messages[info.destHex];
            const c = contacts.find(c => c.keyHex === info.destHex);
            const dest = c ? c.nickname : info.destHex.substring(0, 16) + '...';
            if (msgList && msgList[info.msgIndex]) {
                msgList[info.msgIndex].status = newStatus;
                saveMessages(info.destHex);
                log(`Message to ${dest} → ${newStatus}`);
            }
            delete sentMessageMap[sid];
            cleanSentMessageMap();
        }

        // === SEND MESSAGE ===
        function sendMessage() {
            if (!messageInput.value.trim() || !activeContact.value) return;
            const text = messageInput.value.trim();
            const destHex = activeContact.value.keyHex;

            const srvIdx = findServerForPeer(destHex);
            if (srvIdx < 0) { log('No connected server available'); return; }
            const srv = servers[srvIdx];

            const [mPoint, j] = koblitz.encode(text);
            log(`Koblitz encode: "${text.substring(0, 30)}${text.length > 30 ? '...' : ''}" → point (j=${j})`);
            const destPt = hexToPoint(destHex);
            const destPubKey = Point.decompress(destPt.x, destPt.parity, curve);
            const dh = new DiffieHellman(dhPrivateKey.value, CURVE_NAME);
            const shared = dh.computeSharedSecret(destPubKey);
            log(`DH shared secret computed (x: ${shared.x.toString(16).substring(0, 16)}...)`);
            const ePoint = mPoint.mul(shared.x);
            log(`DH encrypt: E = M * shared.x (E.x: ${ePoint.x.toString(16).substring(0, 16)}...)`);
            const c1Point = srv.mo.encrypt(ePoint);
            log(`MO encrypt: C1 = mo.encrypt(E) (C1.x: ${c1Point.x.toString(16).substring(0, 16)}...)`);
            const [c1X, c1Parity] = c1Point.compress();

            const [eX, eParity] = ePoint.compress();

            if (!messages[destHex]) messages[destHex] = [];
            const msgIndex = messages[destHex].length;
            messages[destHex].push({ text, sent: true, time: new Date().toLocaleTimeString(), ts: Date.now(), status: 'sending', e_x: eX.toString(16), e_parity: Number(eParity), j });
            saveMessages(destHex);

            if (!pendingSendQueues[srvIdx]) pendingSendQueues[srvIdx] = [];
            pendingSendQueues[srvIdx].push({ moInstance: srv.mo, destHex, j, msgIndex, srvIdx });

            log(`[${srv.name}] >> MO_SEND_INIT to ${activeContact.value.nickname} (j=${j}, ${text.length} chars)`);
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
            exportKeys, importKeys, triggerImport, importFileInput,
        };
    },
}).mount('#app');
