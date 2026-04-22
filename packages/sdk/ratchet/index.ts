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
 * Types
 * ================================================================ */

export interface KeyPair {
  publicKey: Buffer;  // 65 bytes — uncompressed P-256
  privateKey: Buffer; // 32 bytes
}

export interface SessionState {
  /* peer identity */
  myIdentityPublicKey: Buffer;
  peerIdentityPublicKey: Buffer;

  /* Double Ratchet core */
  rootKey: Buffer;           // 32 bytes
  sendingChainKey: Buffer;   // 32 bytes (zeros until first DH ratchet)
  receivingChainKey: Buffer; // 32 bytes (zeros until first DH ratchet)

  /* DH ratchet keys */
  myRatchetKeyPair: KeyPair;
  theirRatchetPublicKey: Buffer | null;

  /* counters */
  sendCount: number;
  recvCount: number;
  prevSendCount: number;

  /* skipped message keys: "hexPub:msgNum" → messageKey */
  skippedKeys: Map<string, Buffer>;

  isPostCompromise: boolean;

  /* ---- deferred DH-ratchet init (consumed on first send/receive) ---- */
  peerSPK: Buffer | null;       // peer's signed pre-key, for initiator role (consumed after first send)
  mySPKPair: KeyPair | null;    // my signed pre-key pair, for responder role
  preInitRootKey: Buffer | null; // rootKey snapshot before first send (for simultaneous-send)
  sentBeforeRecv: boolean;       // true if we sent at least one message before receiving any
  peerSPKPublic: Buffer | null;  // permanent copy of peer's SPK public key (for simultaneous detection)

  /* ---- legacy aliases (backward compat) ---- */
  identityKey: Uint8Array;
  signedPreKey: Uint8Array;
  oneTimePreKey: Uint8Array;
  sendingChainMessageNumber: number;
  receivingChainMessageNumber: number;
  previousSendingChainLength: number;
}

/* ================================================================
 * Constants
 * ================================================================ */

const CURVE = 'prime256v1';
const PUB_LEN = 65;        // uncompressed P-256 public key
const HEADER_LEN = 85;     // 65 + 4 + 4 + 12
const MAX_SKIP = 256;

/* ================================================================
 * Init (no-op — Node.js crypto is always ready)
 * ================================================================ */

export async function initializeCrypto(): Promise<void> {}

/* ================================================================
 * Key generation
 * ================================================================ */

export function generateKeyPair(): KeyPair {
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
function ecdhSecret(priv: Buffer, pub: Buffer): Buffer {
  const ecdh = crypto.createECDH(CURVE);
  ecdh.setPrivateKey(priv);
  return Buffer.from(ecdh.computeSecret(pub));
}

/** HKDF-SHA256 */
function hkdf(ikm: Buffer, salt: Buffer, info: string, len: number): Buffer {
  return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len));
}

/** Root-key KDF → new rootKey + chainKey */
function kdfRK(rk: Buffer, dhOut: Buffer): { rootKey: Buffer; chainKey: Buffer } {
  const d = hkdf(dhOut, rk, 'stvor-rk', 64);
  return {
    rootKey: Buffer.from(d.subarray(0, 32)),
    chainKey: Buffer.from(d.subarray(32, 64)),
  };
}

/** Chain-key KDF → new chainKey + messageKey */
function kdfCK(ck: Buffer): { chainKey: Buffer; messageKey: Buffer } {
  return {
    chainKey: Buffer.from(
      crypto.createHmac('sha256', ck).update('\x01').digest(),
    ),
    messageKey: Buffer.from(
      crypto.createHmac('sha256', ck).update('\x02').digest(),
    ),
  };
}

/** AES-256-GCM encrypt with AAD */
function aeadEnc(key: Buffer, pt: Buffer, nonce: Buffer, aad: Buffer): Buffer {
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  c.setAAD(aad);
  const enc = Buffer.concat([c.update(pt), c.final()]);
  return Buffer.concat([enc, c.getAuthTag()]); // ciphertext ‖ 16-byte tag
}

/** AES-256-GCM decrypt with AAD */
function aeadDec(key: Buffer, ct: Buffer, nonce: Buffer, aad: Buffer): Buffer {
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  d.setAAD(aad);
  d.setAuthTag(ct.subarray(-16));
  return Buffer.concat([d.update(ct.subarray(0, -16)), d.final()]);
}

/* ================================================================
 * ECDSA P-256  — sign / verify
 * ================================================================ */

function toPrivKeyObj(pub: Buffer, priv: Buffer): crypto.KeyObject {
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

function toPubKeyObj(pub: Buffer): crypto.KeyObject {
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
export function ecSign(data: Buffer, kp: KeyPair): Buffer {
  return Buffer.from(
    crypto.sign('sha256', data, toPrivKeyObj(kp.publicKey, kp.privateKey)),
  );
}

/** ECDSA-P256-SHA256 verify */
export function ecVerify(data: Buffer, sig: Buffer, pub: Buffer): boolean {
  return crypto.verify('sha256', data, toPubKeyObj(pub), sig);
}

/* ================================================================
 * X3DH — Symmetric Variant with proper DH ordering
 *
 * Implements the full Signal Protocol X3DH key agreement:
 *   DH1 = IK_A × IK_B          # Identity authentication
 *   DH2 = IK_A × SPK_B         # Initiator identity × Responder SPK
 *   DH3 = SPK_A × IK_B         # Initiator SPK × Responder identity
 *   DH4 = SPK_A × OPK_B        # Initiator SPK × Responder OTP (optional)
 *
 * Both sides independently derive the SAME shared secret.
 * Canonical ordering ensures deterministic computation.
 * ================================================================ */

export function x3dhSymmetric(
  myIK: KeyPair,
  mySPK: KeyPair,
  peerIK: Buffer,
  peerSPK: Buffer,
  peerOPK?: Buffer, // Optional one-time prekey
): Buffer {
  // Determine canonical ordering: sort identity keys to ensure both sides compute same result
  const iAmLower = Buffer.compare(myIK.publicKey, peerIK) < 0;
  
  // Create canonical ordering of IKs for consistent salt
  const lowerIK = iAmLower ? myIK.publicKey : peerIK;
  const upperIK = iAmLower ? peerIK : myIK.publicKey;

  // DH1: Identity key agreement (CRITICAL for authentication binding)
  const dh1 = ecdhSecret(myIK.privateKey, peerIK);

  // DH2: Initiator identity × Responder SPK
  const dh2 = iAmLower
    ? ecdhSecret(myIK.privateKey, peerSPK)
    : ecdhSecret(mySPK.privateKey, peerIK);

  // DH3: Initiator SPK × Responder identity  
  const dh3 = iAmLower
    ? ecdhSecret(mySPK.privateKey, peerIK)
    : ecdhSecret(myIK.privateKey, peerSPK);

  // DH4: Initiator SPK × Responder OTP (if available)
  const dh4Buffers: Buffer[] = [dh1, dh2, dh3];
  if (peerOPK && peerOPK.length === PUB_LEN) {
    dh4Buffers.push(ecdhSecret(mySPK.privateKey, peerOPK));
  }

  // Combine all DH outputs with proper domain separation
  const ikm = Buffer.concat(dh4Buffers);
  
  // Use canonical ordering for salt so both sides compute the same value
  const salt = Buffer.concat([
    Buffer.from('X3DH-SALT'),
    lowerIK,
    upperIK,
  ]);

  return hkdf(ikm, salt, 'X3DH-SK', 32);
}

/* ================================================================
 * Session Establishment
 *
 * Creates a "pending" session.  The first send triggers an
 * initiator DH ratchet; the first receive triggers a responder
 * DH ratchet.  Either side can go first.
 * ================================================================ */

export function establishSession(
  myIK: KeyPair,
  mySPK: KeyPair,
  peerIK: Buffer,
  peerSPK: Buffer,
): SessionState {
  const sk = x3dhSymmetric(myIK, mySPK, peerIK, peerSPK);
  const ratchetKP = generateKeyPair();

  return {
    myIdentityPublicKey: Buffer.from(myIK.publicKey),
    peerIdentityPublicKey: Buffer.from(peerIK),

    rootKey: sk,                       // raw shared secret
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
    preInitRootKey: Buffer.from(sk), // saved for simultaneous-send recovery
    sentBeforeRecv: false,
    peerSPKPublic: Buffer.from(peerSPK), // permanent copy for simultaneous-send detection

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

export function encryptMessage(
  session: SessionState,
  plaintext: Buffer,
): { ciphertext: Buffer; header: Buffer } {
  /* ---- Deferred init: initiator DH ratchet on first send ---- */
  if (!session.theirRatchetPublicKey && session.peerSPK) {
    const dhOut = ecdhSecret(session.myRatchetKeyPair.privateKey, session.peerSPK);
    const r = kdfRK(session.rootKey, dhOut);
    session.rootKey = r.rootKey;
    session.sendingChainKey = r.chainKey;
    session.theirRatchetPublicKey = Buffer.from(session.peerSPK);
    session.peerSPK = null;   // consumed
    session.sentBeforeRecv = true; // flag: we sent before receiving anything
    // NOTE: mySPKPair is kept alive so that decryptMessage can use it
    // in the simultaneous-send case (when both sides are initiators).
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

function skipKeys(s: SessionState, until: number): void {
  if (until - s.recvCount > MAX_SKIP) throw new Error('Too many skipped messages');
  while (s.recvCount < until) {
    const { chainKey, messageKey } = kdfCK(s.receivingChainKey);
    s.receivingChainKey = chainKey;
    s.skippedKeys.set(
      `${s.theirRatchetPublicKey!.toString('hex')}:${s.recvCount}`,
      messageKey,
    );
    s.recvCount++;
  }
}

function dhRatchetStep(s: SessionState, theirNewKey: Buffer): void {
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

export function decryptMessage(
  session: SessionState,
  ciphertext: Buffer,
  header: Buffer,
): Buffer {
  const theirPub = header.subarray(0, PUB_LEN);
  const prevChain = header.readUInt32BE(PUB_LEN);
  const msgNum = header.readUInt32BE(PUB_LEN + 4);
  const nonce = header.subarray(PUB_LEN + 8, HEADER_LEN);

  /* ---- Deferred init: pure responder (never sent first) ---- */
  if (!session.theirRatchetPublicKey && session.mySPKPair) {
    // We haven't sent yet — use our SPK as the ratchet key so that
    // DH(mySPK, theirRatchetKey) matches initiator's DH(theirRatchetKey, peerSPK).
    session.myRatchetKeyPair = session.mySPKPair;
    session.mySPKPair = null;
    session.peerSPK = null;
    session.preInitRootKey = null;
  }

  /* ---- First-receive-as-initiator ----
   * We sent first (sentBeforeRecv=true) and are receiving for the first time.
   *
   * Two sub-cases requiring different DH base keys:
   *   A) Simultaneous: peer also acted as initiator → DH(mySPK, theirPub) on preInitRootKey
   *   B) Sequential: peer received first → DH(myRatchetKey, theirPub) on current rootKey
   *
   * We try A (simultaneous) first; fall back to B (sequential) on auth failure.
   */
  if (
    session.sentBeforeRecv &&
    session.mySPKPair &&
    session.preInitRootKey &&
    session.theirRatchetPublicKey &&
    Buffer.compare(session.theirRatchetPublicKey, theirPub) !== 0
  ) {
    // -- Try path A: simultaneous -------------------------------------------
    // Snapshot the fields that differ between the two paths
    const snap = {
      rootKey: Buffer.from(session.rootKey),
      myRatchetKeyPair: session.myRatchetKeyPair,
      theirRatchetPublicKey: session.theirRatchetPublicKey,
      sendCount: session.sendCount,
      recvCount: session.recvCount,
      prevSendCount: session.prevSendCount,
      sendingChainKey: Buffer.from(session.sendingChainKey),
      receivingChainKey: Buffer.from(session.receivingChainKey),
    };

    session.myRatchetKeyPair = session.mySPKPair;
    session.rootKey = session.preInitRootKey;
    session.mySPKPair = null;
    session.preInitRootKey = null;
    session.sentBeforeRecv = false;

    skipKeys(session, prevChain);
    dhRatchetStep(session, theirPub);
    skipKeys(session, msgNum);
    const ckA = kdfCK(session.receivingChainKey);
    session.receivingChainKey = ckA.chainKey;
    session.recvCount++;
    session.receivingChainMessageNumber = session.recvCount;
    try {
      return aeadDec(ckA.messageKey, ciphertext, nonce, header);
    } catch {
      // Path A failed — restore snapshot and try path B: sequential
    }

    // -- Path B: sequential -------------------------------------------------
    // Restore snapshot
    session.rootKey = snap.rootKey;
    session.myRatchetKeyPair = snap.myRatchetKeyPair;
    session.theirRatchetPublicKey = snap.theirRatchetPublicKey;
    session.sendCount = snap.sendCount;
    session.recvCount = snap.recvCount;
    session.prevSendCount = snap.prevSendCount;
    session.sendingChainKey = snap.sendingChainKey;
    session.receivingChainKey = snap.receivingChainKey;
    session.mySPKPair = null;
    session.preInitRootKey = null;
    session.sentBeforeRecv = false;

    skipKeys(session, prevChain);
    dhRatchetStep(session, theirPub);
    skipKeys(session, msgNum);
    const ckB = kdfCK(session.receivingChainKey);
    session.receivingChainKey = ckB.chainKey;
    session.recvCount++;
    session.receivingChainMessageNumber = session.recvCount;
    return aeadDec(ckB.messageKey, ciphertext, nonce, header);
  }

  // 1. Try skipped key
  const skId = `${theirPub.toString('hex')}:${msgNum}`;
  const skMK = session.skippedKeys.get(skId);
  if (skMK) {
    session.skippedKeys.delete(skId);
    return aeadDec(skMK, ciphertext, nonce, header);
  }

  // 2. DH ratchet if new ratchet key
  const needsRatchet =
    !session.theirRatchetPublicKey ||
    Buffer.compare(session.theirRatchetPublicKey, theirPub) !== 0;

  if (needsRatchet) {
    if (session.theirRatchetPublicKey) {
      skipKeys(session, prevChain);
    }
    dhRatchetStep(session, theirPub);
    session.preInitRootKey = null; // no longer needed after first normal ratchet
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

export function forceRatchet(session: SessionState): void {
  session.myRatchetKeyPair = generateKeyPair();
  session.sendCount = 0;
  session.recvCount = 0;
  session.prevSendCount = 0;
  session.isPostCompromise = true;
}

/* ================================================================
 * Serialisation / Deserialisation
 * ================================================================ */

export function serializeSession(s: SessionState): Buffer {
  const sk: Record<string, number[]> = {};
  for (const [k, v] of s.skippedKeys) sk[k] = Array.from(v);

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
    pirk: s.preInitRootKey ? Array.from(s.preInitRootKey) : null,
    sbr: s.sentBeforeRecv ? 1 : 0,
    pspkpub: s.peerSPKPublic ? Array.from(s.peerSPKPublic) : null,
  }));
}

export function deserializeSession(data: Buffer): SessionState {
  const o = JSON.parse(data.toString());
  const skipped = new Map<string, Buffer>();
  if (o.sk) {
    for (const [k, v] of Object.entries(o.sk)) {
      skipped.set(k, Buffer.from(v as number[]));
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
    preInitRootKey: o.pirk ? Buffer.from(o.pirk) : null,
    sentBeforeRecv: o.sbr === 1,
    peerSPKPublic: o.pspkpub ? Buffer.from(o.pspkpub) : null,
    identityKey: myIK,
    signedPreKey: myIK,
    oneTimePreKey: new Uint8Array(0),
    sendingChainMessageNumber: o.sc,
    receivingChainMessageNumber: o.rc,
    previousSendingChainLength: o.psc,
  };
}
