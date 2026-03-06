import { createHash } from 'crypto';
import { Pool } from 'pg';
// PostgreSQL connection pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, // Ensure DATABASE_URL is set in the environment
});
/**
 * Generate a SHA-256 fingerprint for a given public key.
 * @param publicKey - The public key to fingerprint.
 * @returns The fingerprint as a hex string.
 */
export function generateFingerprint(publicKey) {
    const hash = createHash('sha256');
    hash.update(publicKey);
    return hash.digest('hex');
}
/**
 * Store the fingerprint in the database.
 * @param userId - The user ID associated with the fingerprint.
 * @param fingerprint - The fingerprint to store.
 */
export async function storeFingerprint(userId, fingerprint) {
    const client = await pool.connect();
    try {
        await client.query('INSERT INTO fingerprints (user_id, fingerprint) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET fingerprint = $2', [userId, fingerprint]);
    }
    finally {
        client.release();
    }
}
/**
 * Verify the fingerprint against the stored value.
 * @param userId - The user ID associated with the fingerprint.
 * @param fingerprint - The fingerprint to verify.
 * @returns True if the fingerprint matches, false otherwise.
 */
export async function verifyFingerprint(userId, fingerprint) {
    const client = await pool.connect();
    try {
        const result = await client.query('SELECT fingerprint FROM fingerprints WHERE user_id = $1', [userId]);
        if (result.rows.length === 0) {
            // First use: store the fingerprint
            await storeFingerprint(userId, fingerprint);
            return true;
        }
        return result.rows[0].fingerprint === fingerprint;
    }
    finally {
        client.release();
    }
}
/**
 * Honest TOFU Limitations
 *
 * 1. First-session MITM risk: The first connection assumes trust.
 * 2. Fingerprint mismatches result in hard failure.
 * 3. No automatic recovery from key substitution attacks.
 */
export function handleFingerprintMismatch(userId) {
    console.error(`SECURITY ALERT: Fingerprint mismatch detected for user ${userId}`);
    throw new Error('Fingerprint mismatch detected. Connection aborted.');
}
