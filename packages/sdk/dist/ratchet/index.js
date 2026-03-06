/**
 * X3DH + Double Ratchet Implementation
 * Uses ONLY Node.js built-in crypto module — zero external dependencies
 *
 * Implements the Signal Protocol Double Ratchet with deferred initialization:
 *   - First send  → "initiator" DH ratchet (DH with peer's SPK)
 *   - First receive → "responder" DH ratchet (use own SPK, then fresh key)
 * This allows either side to send first after symmetric X3DH key agreement.
 *
 * Provides:
 *   - X3DH key agreement (symmetric variant, both sides derive same SK)
 *   - Double Ratchet with DH ratchet + symmetric-key ratchet
 *   - AES-256-GCM AEAD encryption with header as AAD
 *   - ECDSA P-256 signing / verification
 *   - HKDF-SHA256 key derivation
 *   - HMAC-based chain-key ratchet (Signal-style)
 */
import crypto from 'crypto';
/* ================================================================
 * Constants
 * ================================================================ */
const CURVE = 'prime256v1';
const PUB_LEN = 65; // uncompressed P-256 public key
const HEADER_LEN = 85; // 65 + 4 + 4 + 12
const MAX_SKIP = 256;
/* ================================================================
 * Init (no-op — Node.js crypto is always ready)
 * ================================================================ */
export async function initializeCrypto() { }
/* ================================================================
 * Key generation
 * ================================================================ */
export function generateKeyPair() {
    const ecdh = crypto.createECDH(CURVE);
    ecdh.generateKeys();
    return {
        publicKey: Buffer.from(ecdh.getPublicKey()),
        privateKey: Buffer.from(ecdh.getPrivateKey()),
    };
}
/* ================================================================
 * Low-level crypto helpers
 * ================================================================ */
/** ECDH shared secret */
function ecdhSecret(priv, pub) {
    const ecdh = crypto.createECDH(CURVE);
    ecdh.setPrivateKey(priv);
    return Buffer.from(ecdh.computeSecret(pub));
}
/** HKDF-SHA256 */
function hkdf(ikm, salt, info, len) {
    return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len));
}
/** Root-key KDF → new rootKey + chainKey */
function kdfRK(rk, dhOut) {
    const d = hkdf(dhOut, rk, 'stvor-rk', 64);
    return {
        rootKey: Buffer.from(d.subarray(0, 32)),
        chainKey: Buffer.from(d.subarray(32, 64)),
    };
}
/** Chain-key KDF → new chainKey + messageKey */
function kdfCK(ck) {
    return {
        chainKey: Buffer.from(crypto.createHmac('sha256', ck).update('\x01').digest()),
        messageKey: Buffer.from(crypto.createHmac('sha256', ck).update('\x02').digest()),
    };
}
/** AES-256-GCM encrypt with AAD */
function aeadEnc(key, pt, nonce, aad) {
    const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
    c.setAAD(aad);
    const enc = Buffer.concat([c.update(pt), c.final()]);
    return Buffer.concat([enc, c.getAuthTag()]); // ciphertext ‖ 16-byte tag
}
/** AES-256-GCM decrypt with AAD */
function aeadDec(key, ct, nonce, aad) {
    const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    d.setAAD(aad);
    d.setAuthTag(ct.subarray(-16));
    return Buffer.concat([d.update(ct.subarray(0, -16)), d.final()]);
}
/* ================================================================
 * ECDSA P-256  — sign / verify
 * ================================================================ */
function toPrivKeyObj(pub, priv) {
    return crypto.createPrivateKey({
        key: {
            kty: 'EC', crv: 'P-256',
            x: pub.subarray(1, 33).toString('base64url'),
            y: pub.subarray(33, 65).toString('base64url'),
            d: priv.toString('base64url'),
        },
        format: 'jwk',
    });
}
function toPubKeyObj(pub) {
    return crypto.createPublicKey({
        key: {
            kty: 'EC', crv: 'P-256',
            x: pub.subarray(1, 33).toString('base64url'),
            y: pub.subarray(33, 65).toString('base64url'),
        },
        format: 'jwk',
    });
}
/** ECDSA-P256-SHA256 sign */
export function ecSign(data, kp) {
    return Buffer.from(crypto.sign('sha256', data, toPrivKeyObj(kp.publicKey, kp.privateKey)));
}
/** ECDSA-P256-SHA256 verify */
export function ecVerify(data, sig, pub) {
    return crypto.verify('sha256', data, toPubKeyObj(pub), sig);
}
/* ================================================================
 * X3DH — Symmetric Variant
 *
 * Both sides independently derive the SAME shared secret from
 * their own (IK, SPK) and the peer's (IK, SPK).
 * Canonical ordering by comparing IK public keys.
 * ================================================================ */
export function x3dhSymmetric(myIK, mySPK, peerIK, peerSPK) {
    const iAmLower = Buffer.compare(myIK.publicKey, peerIK) < 0;
    const d1 = iAmLower
        ? ecdhSecret(myIK.privateKey, peerSPK)
        : ecdhSecret(mySPK.privateKey, peerIK);
    const d2 = iAmLower
        ? ecdhSecret(mySPK.privateKey, peerIK)
        : ecdhSecret(myIK.privateKey, peerSPK);
    const d3 = ecdhSecret(mySPK.privateKey, peerSPK);
    return hkdf(Buffer.concat([d1, d2, d3]), Buffer.alloc(32), 'X3DH', 32);
}
/* ================================================================
 * Session Establishment
 *
 * Creates a "pending" session.  The first send triggers an
 * initiator DH ratchet; the first receive triggers a responder
 * DH ratchet.  Either side can go first.
 * ================================================================ */
export function establishSession(myIK, mySPK, peerIK, peerSPK) {
    const sk = x3dhSymmetric(myIK, mySPK, peerIK, peerSPK);
    const ratchetKP = generateKeyPair();
    return {
        myIdentityPublicKey: Buffer.from(myIK.publicKey),
        peerIdentityPublicKey: Buffer.from(peerIK),
        rootKey: sk, // raw shared secret
        sendingChainKey: Buffer.alloc(32), // set by first DH ratchet
        receivingChainKey: Buffer.alloc(32),
        myRatchetKeyPair: ratchetKP,
        theirRatchetPublicKey: null,
        sendCount: 0,
        recvCount: 0,
        prevSendCount: 0,
        skippedKeys: new Map(),
        isPostCompromise: false,
        /* deferred init data */
        peerSPK: Buffer.from(peerSPK),
        mySPKPair: {
            publicKey: Buffer.from(mySPK.publicKey),
            privateKey: Buffer.from(mySPK.privateKey),
        },
        /* legacy compat */
        identityKey: myIK.publicKey,
        signedPreKey: mySPK.publicKey,
        oneTimePreKey: new Uint8Array(0),
        sendingChainMessageNumber: 0,
        receivingChainMessageNumber: 0,
        previousSendingChainLength: 0,
    };
}
/* ================================================================
 * Double Ratchet — Encrypt
 *
 * Header layout (85 bytes):
 *  [0..64]   ratchet public key   (65 B)
 *  [65..68]  prev sending chain length  (u32 BE)
 *  [69..72]  message number             (u32 BE)
 *  [73..84]  AES-GCM nonce              (12 B)
 * ================================================================ */
export function encryptMessage(session, plaintext) {
    /* ---- Deferred init: initiator DH ratchet on first send ---- */
    if (!session.theirRatchetPublicKey && session.peerSPK) {
        const dhOut = ecdhSecret(session.myRatchetKeyPair.privateKey, session.peerSPK);
        const r = kdfRK(session.rootKey, dhOut);
        session.rootKey = r.rootKey;
        session.sendingChainKey = r.chainKey;
        session.theirRatchetPublicKey = Buffer.from(session.peerSPK);
        session.peerSPK = null; // consumed
        session.mySPKPair = null;
    }
    /* ---- Symmetric ratchet ---- */
    const { chainKey, messageKey } = kdfCK(session.sendingChainKey);
    session.sendingChainKey = chainKey;
    const nonce = crypto.randomBytes(12);
    const header = Buffer.alloc(HEADER_LEN);
    session.myRatchetKeyPair.publicKey.copy(header, 0);
    header.writeUInt32BE(session.prevSendCount, PUB_LEN);
    header.writeUInt32BE(session.sendCount, PUB_LEN + 4);
    nonce.copy(header, PUB_LEN + 8);
    const ct = aeadEnc(messageKey, plaintext, nonce, header);
    session.sendCount++;
    session.sendingChainMessageNumber = session.sendCount;
    return { ciphertext: ct, header };
}
/* ================================================================
 * Double Ratchet — Decrypt
 * ================================================================ */
function skipKeys(s, until) {
    if (until - s.recvCount > MAX_SKIP)
        throw new Error('Too many skipped messages');
    while (s.recvCount < until) {
        const { chainKey, messageKey } = kdfCK(s.receivingChainKey);
        s.receivingChainKey = chainKey;
        s.skippedKeys.set(`${s.theirRatchetPublicKey.toString('hex')}:${s.recvCount}`, messageKey);
        s.recvCount++;
    }
}
function dhRatchetStep(s, theirNewKey) {
    s.prevSendCount = s.sendCount;
    s.sendCount = 0;
    s.recvCount = 0;
    s.theirRatchetPublicKey = Buffer.from(theirNewKey);
    // Derive receiving chain
    const dh1 = ecdhSecret(s.myRatchetKeyPair.privateKey, theirNewKey);
    const r1 = kdfRK(s.rootKey, dh1);
    s.rootKey = r1.rootKey;
    s.receivingChainKey = r1.chainKey;
    // New ratchet key pair → derive sending chain
    s.myRatchetKeyPair = generateKeyPair();
    const dh2 = ecdhSecret(s.myRatchetKeyPair.privateKey, theirNewKey);
    const r2 = kdfRK(s.rootKey, dh2);
    s.rootKey = r2.rootKey;
    s.sendingChainKey = r2.chainKey;
}
export function decryptMessage(session, ciphertext, header) {
    const theirPub = header.subarray(0, PUB_LEN);
    const prevChain = header.readUInt32BE(PUB_LEN);
    const msgNum = header.readUInt32BE(PUB_LEN + 4);
    const nonce = header.subarray(PUB_LEN + 8, HEADER_LEN);
    /* ---- Deferred init: responder role on first receive ---- */
    if (!session.theirRatchetPublicKey && session.mySPKPair) {
        // Use our SPK as ratchet key for the first DH step
        // so DH(mySPK, theirRatchetKey) matches initiator's DH(theirRatchetKey, mySPK)
        session.myRatchetKeyPair = session.mySPKPair;
        session.mySPKPair = null; // consumed
        session.peerSPK = null;
    }
    // 1. Try skipped key
    const skId = `${theirPub.toString('hex')}:${msgNum}`;
    const skMK = session.skippedKeys.get(skId);
    if (skMK) {
        session.skippedKeys.delete(skId);
        return aeadDec(skMK, ciphertext, nonce, header);
    }
    // 2. DH ratchet if new ratchet key
    const needsRatchet = !session.theirRatchetPublicKey ||
        Buffer.compare(session.theirRatchetPublicKey, theirPub) !== 0;
    if (needsRatchet) {
        if (session.theirRatchetPublicKey) {
            skipKeys(session, prevChain);
        }
        dhRatchetStep(session, theirPub);
    }
    // 3. Skip to this message number
    skipKeys(session, msgNum);
    // 4. Derive message key
    const { chainKey, messageKey } = kdfCK(session.receivingChainKey);
    session.receivingChainKey = chainKey;
    session.recvCount++;
    session.receivingChainMessageNumber = session.recvCount;
    return aeadDec(messageKey, ciphertext, nonce, header);
}
/* ================================================================
 * Force Ratchet (post-compromise security)
 * ================================================================ */
export function forceRatchet(session) {
    session.myRatchetKeyPair = generateKeyPair();
    session.sendCount = 0;
    session.recvCount = 0;
    session.prevSendCount = 0;
    session.isPostCompromise = true;
}
/* ================================================================
 * Serialisation / Deserialisation
 * ================================================================ */
export function serializeSession(s) {
    const sk = {};
    for (const [k, v] of s.skippedKeys)
        sk[k] = Array.from(v);
    return Buffer.from(JSON.stringify({
        myIK: Array.from(s.myIdentityPublicKey),
        peerIK: Array.from(s.peerIdentityPublicKey),
        rk: Array.from(s.rootKey),
        sck: Array.from(s.sendingChainKey),
        rck: Array.from(s.receivingChainKey),
        mrk: {
            pub: Array.from(s.myRatchetKeyPair.publicKey),
            priv: Array.from(s.myRatchetKeyPair.privateKey),
        },
        trpk: s.theirRatchetPublicKey ? Array.from(s.theirRatchetPublicKey) : null,
        sc: s.sendCount, rc: s.recvCount, psc: s.prevSendCount,
        sk, ipc: s.isPostCompromise ? 1 : 0,
        pspk: s.peerSPK ? Array.from(s.peerSPK) : null,
        mspk: s.mySPKPair
            ? { pub: Array.from(s.mySPKPair.publicKey), priv: Array.from(s.mySPKPair.privateKey) }
            : null,
    }));
}
export function deserializeSession(data) {
    const o = JSON.parse(data.toString());
    const skipped = new Map();
    if (o.sk) {
        for (const [k, v] of Object.entries(o.sk)) {
            skipped.set(k, Buffer.from(v));
        }
    }
    const myIK = Buffer.from(o.myIK);
    return {
        myIdentityPublicKey: myIK,
        peerIdentityPublicKey: Buffer.from(o.peerIK),
        rootKey: Buffer.from(o.rk),
        sendingChainKey: Buffer.from(o.sck),
        receivingChainKey: Buffer.from(o.rck),
        myRatchetKeyPair: {
            publicKey: Buffer.from(o.mrk.pub),
            privateKey: Buffer.from(o.mrk.priv),
        },
        theirRatchetPublicKey: o.trpk ? Buffer.from(o.trpk) : null,
        sendCount: o.sc, recvCount: o.rc, prevSendCount: o.psc,
        skippedKeys: skipped,
        isPostCompromise: o.ipc === 1,
        peerSPK: o.pspk ? Buffer.from(o.pspk) : null,
        mySPKPair: o.mspk
            ? { publicKey: Buffer.from(o.mspk.pub), privateKey: Buffer.from(o.mspk.priv) }
            : null,
        identityKey: myIK,
        signedPreKey: myIK,
        oneTimePreKey: new Uint8Array(0),
        sendingChainMessageNumber: o.sc,
        receivingChainMessageNumber: o.rc,
        previousSendingChainLength: o.psc,
    };
}
