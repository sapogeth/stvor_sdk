/**
 * LocalStorage-based Identity Store for browser environments
 * Implements IIdentityStore for persistent identity key storage
 */
/**
 * Browser-based identity storage using localStorage
 * CRITICAL: Keys are stored in base64url — in production, use encrypted storage
 */
export class LocalStorageIdentityStore {
    constructor(userId, storageKeyPrefix = 'stvor_identity_') {
        this.storageKey = `${storageKeyPrefix}${userId}`;
    }
    async saveIdentityKeys(userId, keys) {
        try {
            const data = {
                identityKeyPair: keys.identityKeyPair,
                signedPreKeyPair: keys.signedPreKeyPair,
                signedPreKeySignature: keys.signedPreKeySignature,
            };
            localStorage.setItem(this.storageKey, JSON.stringify(data));
            console.log(`[LocalStorageIdentityStore] Keys saved for user: ${userId}`);
        }
        catch (error) {
            console.error('[LocalStorageIdentityStore] Failed to save keys:', error);
            throw new Error('Failed to save identity keys to localStorage');
        }
    }
    async loadIdentityKeys(userId) {
        try {
            const data = localStorage.getItem(this.storageKey);
            if (!data) {
                console.log(`[LocalStorageIdentityStore] No keys found for user: ${userId}`);
                return null;
            }
            const parsed = JSON.parse(data);
            console.log(`[LocalStorageIdentityStore] Keys loaded for user: ${userId}`);
            return {
                identityKeyPair: parsed.identityKeyPair,
                signedPreKeyPair: parsed.signedPreKeyPair,
                signedPreKeySignature: parsed.signedPreKeySignature,
            };
        }
        catch (error) {
            console.error('[LocalStorageIdentityStore] Failed to load keys:', error);
            return null;
        }
    }
    /** Delete stored keys (for logout / account reset) */
    async deleteIdentityKeys(userId) {
        localStorage.removeItem(this.storageKey);
        console.log(`[LocalStorageIdentityStore] Keys deleted for user: ${userId}`);
    }
}
/**
 * Session storage implementation for browser environments
 */
export class LocalStorageSessionStore {
    constructor(userId, storageKeyPrefix = 'stvor_session_') {
        this.storageKey = `${storageKeyPrefix}${userId}`;
    }
    async saveSession(userId, peerId, _session) {
        try {
            const allSessions = this.getAllSessions();
            allSessions[peerId] = { savedAt: Date.now() };
            localStorage.setItem(this.storageKey, JSON.stringify(allSessions));
        }
        catch (error) {
            console.error('[LocalStorageSessionStore] Failed to save session:', error);
        }
    }
    async loadSession(userId, peerId) {
        try {
            const allSessions = this.getAllSessions();
            return allSessions[peerId] || null;
        }
        catch (error) {
            console.error('[LocalStorageSessionStore] Failed to load session:', error);
            return null;
        }
    }
    async deleteSession(userId, peerId) {
        try {
            const allSessions = this.getAllSessions();
            delete allSessions[peerId];
            localStorage.setItem(this.storageKey, JSON.stringify(allSessions));
        }
        catch (error) {
            console.error('[LocalStorageSessionStore] Failed to delete session:', error);
        }
    }
    async listSessions(userId) {
        const allSessions = this.getAllSessions();
        return Object.keys(allSessions);
    }
    getAllSessions() {
        const data = localStorage.getItem(this.storageKey);
        return data ? JSON.parse(data) : {};
    }
}
export default LocalStorageIdentityStore;
