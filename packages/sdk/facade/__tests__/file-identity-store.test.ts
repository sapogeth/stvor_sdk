/**
 * Tests for File-Based Identity Store
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import { FileIdentityStore } from './file-identity-store.js';

test('FileIdentityStore', async (t) => {
  let tmpDir: string;
  let store: FileIdentityStore;

  // Setup temporary directory
  tmpDir = path.join(os.tmpdir(), `stvor-test-${Date.now()}`);
  
  // Cleanup after tests
  t.after(async () => {
    try {
      const files = await fs.readdir(tmpDir);
      for (const f of files) {
        await fs.unlink(path.join(tmpDir, f));
      }
      await fs.rmdir(tmpDir);
    } catch (e) {
      // ignore
    }
  });

  await t.test('should create store with config', () => {
    store = new FileIdentityStore({
      directory: tmpDir,
      masterPassword: 'test-password-123',
    });
    assert.ok(store, 'Store created');
  });

  await t.test('should save and load identity keys', async () => {
    const testKeys = {
      identityKeyPair: {
        publicKey: 'test-pub-key-alice',
        privateKey: 'test-priv-key-alice',
      },
      signedPreKeyPair: {
        publicKey: 'test-spk-pub',
        privateKey: 'test-spk-priv',
      },
      signedPreKeySignature: 'test-signature',
    };

    // Save
    await store.saveIdentityKeys('alice', testKeys);
    
    // Verify file was created with restricted permissions
    const files = await fs.readdir(tmpDir);
    assert.strictEqual(files.length, 1, 'One file created');
    assert.ok(files[0].endsWith('.keys.enc'), 'File has .keys.enc extension');

    // Load
    const loaded = await store.loadIdentityKeys('alice');
    assert.deepStrictEqual(loaded, testKeys, 'Keys match');
  });

  await t.test('should return null for missing keys', async () => {
    const result = await store.loadIdentityKeys('nonexistent');
    assert.strictEqual(result, null, 'Returns null for missing user');
  });

  await t.test('should handle special characters in userId', async () => {
    const testKeys = {
      identityKeyPair: {
        publicKey: 'pub-key',
        privateKey: 'priv-key',
      },
      signedPreKeyPair: {
        publicKey: 'spk-pub',
        privateKey: 'spk-priv',
      },
      signedPreKeySignature: 'sig',
    };

    const userIds = [
      'alice@example.com',
      'bob+tag@example.co.uk',
      'user/name',
      'user\\name',
      'user|name',
    ];

    for (const userId of userIds) {
      await store.saveIdentityKeys(userId, testKeys);
      const loaded = await store.loadIdentityKeys(userId);
      assert.deepStrictEqual(loaded, testKeys, `Keys restored for ${userId}`);
    }
  });

  await t.test('should encrypt keys (different passwords cannot decrypt)', async () => {
    const testKeys = {
      identityKeyPair: { publicKey: 'pub', privateKey: 'priv' },
      signedPreKeyPair: { publicKey: 'spk-pub', privateKey: 'spk-priv' },
      signedPreKeySignature: 'sig',
    };

    // Save with password1
    const store1 = new FileIdentityStore({
      directory: tmpDir,
      masterPassword: 'password-1',
    });
    await store1.saveIdentityKeys('bob', testKeys);

    // Try to load with password2 (should fail)
    const store2 = new FileIdentityStore({
      directory: tmpDir,
      masterPassword: 'password-2',
    });
    
    let decryptFailed = false;
    try {
      await store2.loadIdentityKeys('bob');
    } catch (e) {
      decryptFailed = true;
    }
    
    assert.ok(decryptFailed, 'Wrong password fails decryption');

    // Load with correct password should work
    const loaded = await store1.loadIdentityKeys('bob');
    assert.deepStrictEqual(loaded, testKeys, 'Correct password decrypts');
  });

  await t.test('should delete identity keys', async () => {
    const testKeys = {
      identityKeyPair: { publicKey: 'pub', privateKey: 'priv' },
      signedPreKeyPair: { publicKey: 'spk-pub', privateKey: 'spk-priv' },
      signedPreKeySignature: 'sig',
    };

    await store.saveIdentityKeys('charlie', testKeys);
    let loaded = await store.loadIdentityKeys('charlie');
    assert.ok(loaded, 'Keys exist before delete');

    await store.deleteIdentityKeys('charlie');
    loaded = await store.loadIdentityKeys('charlie');
    assert.strictEqual(loaded, null, 'Keys deleted');
  });

  await t.test('should list all users', async () => {
    const store3 = new FileIdentityStore({
      directory: tmpDir,
      masterPassword: 'test-pass',
    });

    const testKeys = {
      identityKeyPair: { publicKey: 'pub', privateKey: 'priv' },
      signedPreKeyPair: { publicKey: 'spk-pub', privateKey: 'spk-priv' },
      signedPreKeySignature: 'sig',
    };

    await store3.saveIdentityKeys('user1', testKeys);
    await store3.saveIdentityKeys('user2', testKeys);
    await store3.saveIdentityKeys('user3', testKeys);

    const users = await store3.listUsers();
    assert.ok(users.includes('user1'), 'user1 in list');
    assert.ok(users.includes('user2'), 'user2 in list');
    assert.ok(users.includes('user3'), 'user3 in list');
  });

  await t.test('should handle multiple stores with same directory', async () => {
    const store4a = new FileIdentityStore({
      directory: tmpDir,
      masterPassword: 'shared-pass',
    });

    const store4b = new FileIdentityStore({
      directory: tmpDir,
      masterPassword: 'shared-pass',
    });

    const testKeys = {
      identityKeyPair: { publicKey: 'pub', privateKey: 'priv' },
      signedPreKeyPair: { publicKey: 'spk-pub', privateKey: 'spk-priv' },
      signedPreKeySignature: 'sig',
    };

    await store4a.saveIdentityKeys('shared-user', testKeys);
    const loaded = await store4b.loadIdentityKeys('shared-user');
    assert.deepStrictEqual(loaded, testKeys, 'Different store instances can share data');
  });
});
