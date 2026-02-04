/**
 * Generate recovery key shares using Shamir's Secret Sharing.
 * @param secret - The secret to split (e.g., a recovery key).
 * @returns An array of two shares.
 */
export declare function generateRecoveryShares(secret: Uint8Array): Uint8Array[];
/**
 * Combine recovery key shares to reconstruct the secret.
 * @param shares - An array of shares.
 * @returns The reconstructed secret.
 */
export declare function combineRecoveryShares(shares: Uint8Array[]): Uint8Array;
/**
 * Store recovery shares securely.
 * @param userId - The user ID.
 * @param shares - The recovery shares.
 */
export declare function storeRecoveryShares(userId: string, shares: Uint8Array[]): void;
/**
 * Retrieve recovery shares for a user.
 * @param userId - The user ID.
 * @returns The recovery shares.
 */
export declare function retrieveRecoveryShares(userId: string): Uint8Array[];
/**
 * Revoke recovery shares for a user.
 * @param userId - The user ID.
 */
export declare function revokeRecoveryShares(userId: string): void;
export declare function verifyShareIntegrity(share: Uint8Array, expectedHash: string): boolean;
/**
 * Formal Policy for Recovery Shares
 */
declare const recoveryPolicy: {
    minAdmins: number;
    tamperEvidence: boolean;
};
export declare function getRecoveryPolicy(): typeof recoveryPolicy;
/**
 * Example Admin Authentication Model
 */
export declare function authenticateAdmin(adminToken: string): boolean;
export declare function approveRecovery(userId: string, adminId: string): void;
export declare function revokeRecovery(userId: string, adminId: string): void;
export {};
