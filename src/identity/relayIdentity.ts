import * as crypto from 'crypto';

const RELAY_IDENTITY_KEY = process.env.RELAY_IDENTITY_KEY;

export const relayIdentity = {
  key: undefined as crypto.KeyObject | undefined,
  publicKey: undefined as Buffer | undefined,
  init() {
    if (RELAY_IDENTITY_KEY) {
      this.key = crypto.createPrivateKey({
        key: Buffer.from(RELAY_IDENTITY_KEY, 'base64'),
        format: 'der',
        type: 'pkcs8',
      });
      this.publicKey = crypto.createPublicKey(this.key).export({ type: 'spki', format: 'der' });
    } else {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
      this.key = privateKey;
      this.publicKey = publicKey.export({ type: 'spki', format: 'der' });
    }
  },
};
