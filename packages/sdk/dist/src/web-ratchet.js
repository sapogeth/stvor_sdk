/**
 * Double Ratchet для браузера — Web Crypto API only.
 *
 * Алгоритмы:
 *   Key agreement : ECDH P-256
 *   Signing       : ECDSA P-256 SHA-256
 *   KDF           : HKDF-SHA-256
 *   AEAD          : AES-256-GCM
 *
 * Семантика совпадает с Node.js ядром (ratchet/index.ts):
 *   - X3DH symmetric variant — обе стороны дают одинаковый SK
 *   - Deferred DH ratchet    — первый send/receive инициирует ratchet-шаг
 *   - Skipped keys           — поддержка out-of-order сообщений
 */
/// <reference lib="dom" />
// ─── Утилиты ──────────────────────────────────────────────────────────────────
const subtle = globalThis.crypto.subtle;
function ab(buf) {
    if (buf instanceof ArrayBuffer)
        return buf;
    const v = buf;
    const b = v.buffer;
    if (b instanceof ArrayBuffer)
        return b.slice(v.byteOffset, v.byteOffset + v.byteLength);
    // SharedArrayBuffer — copy to plain ArrayBuffer
    const copy = new Uint8Array(v.byteLength);
    copy.set(new Uint8Array(b, v.byteOffset, v.byteLength));
    return copy.buffer;
}
function concat(...bufs) {
    const total = bufs.reduce((s, b) => s + b.byteLength, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const b of bufs) {
        out.set(new Uint8Array(b), off);
        off += b.byteLength;
    }
    return out.buffer;
}
function u32be(n) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, false);
    return b.buffer;
}
function readU32be(buf, offset) {
    return new DataView(buf).getUint32(offset, false);
}
function randBytes(n) {
    return globalThis.crypto.getRandomValues(new Uint8Array(n));
}
function b64enc(buf) {
    let s = '';
    new Uint8Array(buf).forEach(b => s += String.fromCharCode(b));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function b64dec(s) {
    const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    const a = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++)
        a[i] = b.charCodeAt(i);
    return a.buffer;
}
// ─── Низкоуровневые операции ──────────────────────────────────────────────────
async function generateECDH() {
    const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
    const publicRaw = await subtle.exportKey('raw', kp.publicKey);
    return { publicKey: kp.publicKey, privateKey: kp.privateKey, publicRaw };
}
async function generateECDSA() {
    const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const publicRaw = await subtle.exportKey('raw', kp.publicKey);
    return { publicKey: kp.publicKey, privateKey: kp.privateKey, publicRaw };
}
async function ecdsaSign(data, privateKey) {
    return subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data);
}
async function ecdsaVerify(sig, data, publicRaw) {
    const pub = await subtle.importKey('raw', publicRaw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, sig, data);
}
async function ecdhSecret(myPrivate, theirPublicRaw) {
    const theirPub = await subtle.importKey('raw', theirPublicRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    return subtle.deriveBits({ name: 'ECDH', public: theirPub }, myPrivate, 256);
}
async function hkdf(ikm, salt, info, len) {
    const ikmKey = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(info) }, ikmKey, len * 8);
}
/** Root-key KDF → новый rootKey (32 B) + chainKey (32 B) */
async function kdfRK(rk, dhOut) {
    const out = await hkdf(dhOut, rk, 'stvor-rk', 64);
    return { rootKey: out.slice(0, 32), chainKey: out.slice(32, 64) };
}
/** Chain-key KDF → новый chainKey + messageKey (32 B каждый) */
async function kdfCK(ck) {
    const [chainKey, messageKey] = await Promise.all([
        hkdf(ck, new Uint8Array(32).buffer, 'stvor-chain-key', 32),
        hkdf(ck, new Uint8Array(32).buffer, 'stvor-msg-key', 32),
    ]);
    return { chainKey, messageKey };
}
async function aeadEncrypt(keyRaw, plaintext, aad) {
    const nonceBytes = randBytes(12);
    const nonce = nonceBytes.buffer.slice(nonceBytes.byteOffset, nonceBytes.byteOffset + 12);
    const key = await subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['encrypt']);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, key, plaintext);
    return { ciphertext: ct, nonce: new Uint8Array(nonce) };
}
async function aeadDecrypt(keyRaw, ciphertext, nonce, aad) {
    const key = await subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['decrypt']);
    return subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, key, ciphertext);
}
// ─── Header (85 байт) ─────────────────────────────────────────────────────────
// [0..64] ratchet public key (65 B)
// [65..68] prevSendCount (u32 BE)
// [69..72] msgNum (u32 BE)
// [73..84] nonce (12 B)
function buildHeader(pub, prevSendCount, msgNum, nonce) {
    const h = new Uint8Array(85);
    h.set(new Uint8Array(pub), 0);
    h.set(new Uint8Array(u32be(prevSendCount)), 65);
    h.set(new Uint8Array(u32be(msgNum)), 69);
    h.set(nonce, 73);
    return h.buffer;
}
function parseHeader(h) {
    return {
        pub: h.slice(0, 65),
        prevSendCount: readU32be(h, 65),
        msgNum: readU32be(h, 69),
        nonce: h.slice(73, 85),
    };
}
// ─── X3DH (symmetric variant) ─────────────────────────────────────────────────
async function x3dhSymmetric(myIK, mySPK, peerIKRaw, peerSPKRaw) {
    const myPubBytes = new Uint8Array(myIK.publicRaw);
    const peerPubBytes = new Uint8Array(peerIKRaw);
    const iAmLower = myPubBytes[1] < peerPubBytes[1] ||
        (myPubBytes[1] === peerPubBytes[1] && myPubBytes[2] < peerPubBytes[2]);
    const [dh1, dh2, dh3] = await Promise.all([
        ecdhSecret(myIK.privateKey, peerIKRaw),
        iAmLower
            ? ecdhSecret(myIK.privateKey, peerSPKRaw)
            : ecdhSecret(mySPK.privateKey, peerIKRaw),
        iAmLower
            ? ecdhSecret(mySPK.privateKey, peerIKRaw)
            : ecdhSecret(myIK.privateKey, peerSPKRaw),
    ]);
    const lowerIK = iAmLower ? myIK.publicRaw : peerIKRaw;
    const upperIK = iAmLower ? peerIKRaw : myIK.publicRaw;
    const salt = concat(new TextEncoder().encode('X3DH-SALT').buffer, lowerIK, upperIK);
    const ikm = concat(dh1, dh2, dh3);
    return hkdf(ikm, salt, 'X3DH-SK', 32);
}
// ─── Session establishment ────────────────────────────────────────────────────
export async function webEstablishSession(myIK, mySPK, peerIKRaw, peerSPKRaw) {
    const sk = await x3dhSymmetric(myIK, mySPK, peerIKRaw, peerSPKRaw);
    const ratchetKP = await generateECDH();
    const zero32 = new ArrayBuffer(32);
    return {
        myIdentityPublicRaw: myIK.publicRaw,
        peerIdentityPublicRaw: peerIKRaw,
        rootKey: sk,
        sendingChainKey: zero32,
        receivingChainKey: zero32,
        myRatchetPair: ratchetKP,
        theirRatchetPublicRaw: null,
        sendCount: 0,
        recvCount: 0,
        prevSendCount: 0,
        skippedKeys: new Map(),
        peerSPKRaw: peerSPKRaw,
        mySPKPair: mySPK,
    };
}
// ─── DH ratchet step ──────────────────────────────────────────────────────────
async function dhRatchetStep(s, theirNewKeyRaw) {
    s.prevSendCount = s.sendCount;
    s.sendCount = 0;
    s.recvCount = 0;
    s.theirRatchetPublicRaw = theirNewKeyRaw;
    const dh1 = await ecdhSecret(s.myRatchetPair.privateKey, theirNewKeyRaw);
    const r1 = await kdfRK(s.rootKey, dh1);
    s.rootKey = r1.rootKey;
    s.receivingChainKey = r1.chainKey;
    s.myRatchetPair = await generateECDH();
    const dh2 = await ecdhSecret(s.myRatchetPair.privateKey, theirNewKeyRaw);
    const r2 = await kdfRK(s.rootKey, dh2);
    s.rootKey = r2.rootKey;
    s.sendingChainKey = r2.chainKey;
}
const MAX_SKIP = 256;
async function skipKeys(s, until) {
    if (until - s.recvCount > MAX_SKIP)
        throw new Error('Too many skipped messages');
    while (s.recvCount < until) {
        const { chainKey, messageKey } = await kdfCK(s.receivingChainKey);
        s.receivingChainKey = chainKey;
        const skId = `${b64enc(s.theirRatchetPublicRaw)}:${s.recvCount}`;
        s.skippedKeys.set(skId, messageKey);
        s.recvCount++;
    }
}
// ─── Encrypt ──────────────────────────────────────────────────────────────────
export async function webEncrypt(session, plaintext) {
    // Deferred init — initiator first send
    if (!session.theirRatchetPublicRaw && session.peerSPKRaw) {
        const dhOut = await ecdhSecret(session.myRatchetPair.privateKey, session.peerSPKRaw);
        const r = await kdfRK(session.rootKey, dhOut);
        session.rootKey = r.rootKey;
        session.sendingChainKey = r.chainKey;
        session.theirRatchetPublicRaw = session.peerSPKRaw;
        session.peerSPKRaw = null;
        session.mySPKPair = null;
    }
    const { chainKey, messageKey } = await kdfCK(session.sendingChainKey);
    session.sendingChainKey = chainKey;
    const { ciphertext, nonce } = await aeadEncrypt(messageKey, plaintext, session.myRatchetPair.publicRaw);
    const header = buildHeader(session.myRatchetPair.publicRaw, session.prevSendCount, session.sendCount, nonce);
    session.sendCount++;
    return { ciphertext: b64enc(ciphertext), header: b64enc(header) };
}
// ─── Decrypt ──────────────────────────────────────────────────────────────────
export async function webDecrypt(session, ciphertextB64, headerB64) {
    const headerBuf = b64dec(headerB64);
    const { pub: theirPub, prevSendCount, msgNum, nonce } = parseHeader(headerBuf);
    const ct = b64dec(ciphertextB64);
    // Deferred init — responder first receive
    if (!session.theirRatchetPublicRaw && session.mySPKPair) {
        session.myRatchetPair = session.mySPKPair;
        session.mySPKPair = null;
        session.peerSPKRaw = null;
    }
    const theirPubB64 = b64enc(theirPub);
    // Try skipped key
    const skId = `${theirPubB64}:${msgNum}`;
    const skMK = session.skippedKeys.get(skId);
    if (skMK) {
        session.skippedKeys.delete(skId);
        return aeadDecrypt(skMK, ct, nonce, theirPub);
    }
    // DH ratchet if new public key
    const curPub = session.theirRatchetPublicRaw ? b64enc(session.theirRatchetPublicRaw) : null;
    if (curPub !== theirPubB64) {
        if (session.theirRatchetPublicRaw)
            await skipKeys(session, prevSendCount);
        await dhRatchetStep(session, theirPub);
    }
    await skipKeys(session, msgNum);
    const { chainKey, messageKey } = await kdfCK(session.receivingChainKey);
    session.receivingChainKey = chainKey;
    session.recvCount++;
    return aeadDecrypt(messageKey, ct, nonce, theirPub);
}
export async function generateWebIdentityKeys() {
    const ikEcdsaPair = await generateECDSA();
    const ikEcdhPair = await generateECDH();
    const spkPair = await generateECDH();
    // Sign the SPK public key with the ECDSA identity key
    const spkSig = await ecdsaSign(spkPair.publicRaw, ikEcdsaPair.privateKey);
    return {
        ikEcdsaPair,
        ikEcdhPair,
        spkPair,
        spkSig,
        // ikPair points to the ECDH key (used for X3DH key agreement in webEstablishSession)
        ikPair: ikEcdhPair,
    };
}
export async function verifyWebSPK(spkRaw, sigRaw, ikEcdsaPublicRaw) {
    if (!sigRaw || sigRaw.byteLength === 0) {
        // No signature provided — fail closed (do not accept unsigned SPKs)
        return false;
    }
    return ecdsaVerify(sigRaw, spkRaw, ikEcdsaPublicRaw);
}
export async function serializeWebSession(s) {
    const mrPrivRaw = await subtle.exportKey('pkcs8', s.myRatchetPair.privateKey);
    const skipped = {};
    for (const [k, v] of s.skippedKeys)
        skipped[k] = b64enc(v);
    let mySPKPub = null, mySPKPriv = null;
    if (s.mySPKPair) {
        mySPKPriv = b64enc(await subtle.exportKey('pkcs8', s.mySPKPair.privateKey));
        mySPKPub = b64enc(s.mySPKPair.publicRaw);
    }
    return {
        myIKPub: b64enc(s.myIdentityPublicRaw),
        peerIKPub: b64enc(s.peerIdentityPublicRaw),
        rk: b64enc(s.rootKey),
        sck: b64enc(s.sendingChainKey),
        rck: b64enc(s.receivingChainKey),
        mrPub: b64enc(s.myRatchetPair.publicRaw),
        mrPriv: b64enc(mrPrivRaw),
        trpk: s.theirRatchetPublicRaw ? b64enc(s.theirRatchetPublicRaw) : null,
        sc: s.sendCount,
        rc: s.recvCount,
        psc: s.prevSendCount,
        skipped,
        peerSPK: s.peerSPKRaw ? b64enc(s.peerSPKRaw) : null,
        mySPKPub,
        mySPKPriv,
    };
}
async function importECDHPair(pubRaw, privPkcs8) {
    const [pub, priv] = await Promise.all([
        subtle.importKey('raw', pubRaw, { name: 'ECDH', namedCurve: 'P-256' }, true, []),
        subtle.importKey('pkcs8', privPkcs8, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']),
    ]);
    return { publicKey: pub, privateKey: priv, publicRaw: pubRaw };
}
export async function deserializeWebSession(d) {
    const mrPubRaw = b64dec(d.mrPub);
    const mrPrivRaw = b64dec(d.mrPriv);
    const mrPair = await importECDHPair(mrPubRaw, mrPrivRaw);
    let mySPKPair = null;
    if (d.mySPKPub && d.mySPKPriv) {
        mySPKPair = await importECDHPair(b64dec(d.mySPKPub), b64dec(d.mySPKPriv));
    }
    const skipped = new Map();
    for (const [k, v] of Object.entries(d.skipped))
        skipped.set(k, b64dec(v));
    return {
        myIdentityPublicRaw: b64dec(d.myIKPub),
        peerIdentityPublicRaw: b64dec(d.peerIKPub),
        rootKey: b64dec(d.rk),
        sendingChainKey: b64dec(d.sck),
        receivingChainKey: b64dec(d.rck),
        myRatchetPair: mrPair,
        theirRatchetPublicRaw: d.trpk ? b64dec(d.trpk) : null,
        sendCount: d.sc,
        recvCount: d.rc,
        prevSendCount: d.psc,
        skippedKeys: skipped,
        peerSPKRaw: d.peerSPK ? b64dec(d.peerSPK) : null,
        mySPKPair,
    };
}
