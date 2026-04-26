/**
 * STVOR Crypto Session Manager
 * Uses ONLY Node.js built-in crypto module — zero external dependencies
 *
 * Manages identity keys (IK + SPK), ECDSA signatures,
 * X3DH session establishment, and Double Ratchet encrypt/decrypt.
 */
import { KeyPair } from '../ratchet/index.js';
export interface IdentityKeys {
    identityKeyPair: KeyPair;
    signedPreKeyPair: KeyPair;
    signedPreKeySignature: Buffer;
}
export interface SerializedPublicKeys {
    identityKey: string;
    signedPreKey: string;
    signedPreKeySignature: string;
    oneTimePreKey: string;
    pqcEk?: string;
}
export interface IIdentityStore {
    saveIdentityKeys(userId: string, keys: {
        identityKeyPair: {
            publicKey: string;
            privateKey: string;
        };
        signedPreKeyPair: {
            publicKey: string;
            privateKey: string;
        };
        signedPreKeySignature: string;
    }): Promise<void>;
    loadIdentityKeys(userId: string): Promise<{
        identityKeyPair: {
            publicKey: string;
            privateKey: string;
        };
        signedPreKeyPair: {
            publicKey: string;
            privateKey: string;
        };
        signedPreKeySignature: string;
    } | null>;
}
export interface ISessionStore {
    saveSession(userId: string, peerId: string, sessionData: Buffer): Promise<void>;
    loadSession(userId: string, peerId: string): Promise<Buffer | null>;
    deleteSession(userId: string, peerId: string): Promise<void>;
    listSessions(userId: string): Promise<string[]>;
}
export interface GroupMemberState {
    chainKey: Buffer;
    counter: number;
    generation: number;
    skippedKeys: Map<number, Buffer>;
}
export interface GroupSessionState {
    groupId: string;
    members: Set<string>;
    sendChainKey: Buffer;
    sendCounter: number;
    sendGeneration: number;
    createdAt: number;
    memberStates: Map<string, GroupMemberState>;
}
export declare class CryptoSessionManager {
    private userId;
    private identityKeys;
    private sessions;
    private groupSessions;
    private initialized;
    private initPromise;
    private identityStore;
    private sessionStore;
    private pqcEnabled;
    private pqcKeyPair;
    private peerPqcEks;
    constructor(userId: string, identityStore?: IIdentityStore, sessionStore?: ISessionStore, pqc?: boolean);
    initialize(): Promise<void>;
    private _doInit;
    getIdentityPrivateKey(): Buffer;
    getPublicKeys(): SerializedPublicKeys;
    isPqcEnabled(): boolean;
    /**
     * Encapsulate a shared secret to a peer who has a PQC key.
     * Called by sender during session setup.
     * Returns { ciphertext, pqcSharedSecret } — ciphertext sent to peer in register message.
     */
    pqcEncapsForPeer(peerEkB64: string): {
        ctB64: string;
        ss: Uint8Array;
    };
    /**
     * Decapsulate a PQC ciphertext sent by a peer.
     * Returns the shared secret.
     */
    pqcDecapsFromPeer(ctB64: string): Uint8Array;
    /**
     * Derive hybrid session key combining classical X3DH and PQC shared secrets.
     */
    hybridSessionKey(classicalSS: Uint8Array, pqcSS: Uint8Array): Uint8Array;
    /**
     * Cache a peer's PQC encapsulation key (received during key exchange).
     */
    storePeerPqcEk(peerId: string, ekB64: string): void;
    getPeerPqcEk(peerId: string): Uint8Array | undefined;
    establishSession(peerId: string, peerPublicKeys: SerializedPublicKeys): Promise<void>;
    establishSessionWithPeer(peerId: string, pk: SerializedPublicKeys): Promise<void>;
    hasSession(peerId: string): boolean;
    encryptForPeer(peerId: string, plaintext: string): {
        ciphertext: string;
        header: string;
    };
    decryptFromPeer(peerId: string, ciphertext: string, header: string): string;
    createGroupSession(groupId: string, memberIds: string[]): GroupSessionState;
    getGroupSession(groupId: string): GroupSessionState | undefined;
    hasGroupSession(groupId: string): boolean;
    getSenderKeyDistribution(groupId: string): {
        chainKey: string;
        generation: number;
        counter: number;
    };
    installSenderKey(groupId: string, fromUserId: string, chainKey: string, generation: number): void;
    encryptForGroup(groupId: string, plaintext: string): {
        ciphertext: string;
        groupHeader: string;
    };
    decryptFromGroup(groupId: string, fromUserId: string, ciphertext: string, groupHeader: string): string;
    ratchetGroupSenderKey(groupId: string): {
        chainKey: string;
        generation: number;
    };
    addGroupMember(groupId: string, memberId: string): void;
    removeGroupMember(groupId: string, memberId: string): void;
    getGroupMembers(groupId: string): string[];
    forceRatchet(peerId: string): Promise<void>;
}
