/**
 * Tests for File-Based Session Store
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { FileSessionStore } from './file-session-store.js';

test('FileSessionStore', async (t) => {
  let tmpDir: string;
  let store: FileSessionStore;

  // Setup
  tmpDir = path.join(os.tmpdir(), `stvor-session-test-${Date.now()}`);
  
  // Cleanup
  t.after(async () => {
    try {
      const cleanup = async (dir: string) => {
        const entries = await fs.readdir(dir);
        for (const entry of entries) {
          const entryPath = path.join(dir, entry);
          const stat = await fs.stat(entryPath);
          if (stat.isDirectory()) {
            await cleanup(entryPath);
            await fs.rmdir(entryPath);
          } else {
            await fs.unlink(entryPath);
          }
        }
      };
      await cleanup(tmpDir);
      await fs.rmdir(tmpDir);
    } catch (e) {
      // ignore
    }
  });

  await t.test('should create store with config', () => {
    store = new FileSessionStore({
      directory: tmpDir,
      masterPassword: 'test-password-123',
    });
    assert.ok(store, 'Store created');
  });

  await t.test('should save and load session', async () => {
    const sessionData = Buffer.from('test-session-state-binary-data');

    // Save
    await store.saveSession('alice', 'bob', sessionData);
    
    // Verify file was created
    const userDir = path.join(tmpDir, 'alice');
    const files = await fs.readdir(userDir);
    assert.strictEqual(files.length, 1, 'One session file created');
    assert.ok(files[0].endsWith('.session.enc'), 'File has .session.enc extension');

    // Load
    const loaded = await store.loadSession('alice', 'bob');
    assert.deepStrictEqual(loaded, sessionData, 'Session data matches');
  });

  await t.test('should return null for missing session', async () => {
    const result = await store.loadSession('alice', 'charlie');
    assert.strictEqual(result, null, 'Returns null for missing session');
  });

  await t.test('should save multiple sessions for same user', async () => {
    const session1 = Buffer.from('session-with-bob');
    const session2 = Buffer.from('session-with-charlie');
    const session3 = Buffer.from('session-with-dave');

    await store.saveSession('user1', 'bob', session1);
    await store.saveSession('user1', 'charlie', session2);
    await store.saveSession('user1', 'dave', session3);

    const loaded1 = await store.loadSession('user1', 'bob');
    const loaded2 = await store.loadSession('user1', 'charlie');
    const loaded3 = await store.loadSession('user1', 'dave');

    assert.deepStrictEqual(loaded1, session1, 'Session with bob matches');
    assert.deepStrictEqual(loaded2, session2, 'Session with charlie matches');
    assert.deepStrictEqual(loaded3, session3, 'Session with dave matches');
  });

  await t.test('should encrypt sessions (wrong password cannot decrypt)', async () => {
    const sessionData = Buffer.from('secret-session-state');

    // Save with password1
    const store1 = new FileSessionStore({
      directory: tmpDir,
      masterPassword: 'password-1',
    });
    await store1.saveSession('alice', 'eve', sessionData);

    // Try to load with password2 (should fail)
    const store2 = new FileSessionStore({
      directory: tmpDir,
      masterPassword: 'password-2',
    });
    
    let decryptFailed = false;
    try {
      await store2.loadSession('alice', 'eve');
    } catch (e) {
      decryptFailed = true;
    }
    
    assert.ok(decryptFailed, 'Wrong password fails decryption');

    // Load with correct password should work
    const loaded = await store1.loadSession('alice', 'eve');
    assert.deepStrictEqual(loaded, sessionData, 'Correct password decrypts');
  });

  await t.test('should handle large session data', async () => {
    const largeData = Buffer.alloc(1024 * 100); // 100 KB
    crypto.getRandomValues(largeData);

    await store.saveSession('large-user', 'large-peer', largeData);
    const loaded = await store.loadSession('large-user', 'large-peer');
    assert.deepStrictEqual(loaded, largeData, 'Large session data preserved');
  });

  await t.test('should delete session', async () => {
    const sessionData = Buffer.from('to-be-deleted');

    await store.saveSession('user2', 'peer1', sessionData);
    let loaded = await store.loadSession('user2', 'peer1');
    assert.ok(loaded, 'Session exists before delete');

    await store.deleteSession('user2', 'peer1');
    loaded = await store.loadSession('user2', 'peer1');
    assert.strictEqual(loaded, null, 'Session deleted');
  });

  await t.test('should list all sessions for user', async () => {
    const store3 = new FileSessionStore({
      directory: tmpDir,
      masterPassword: 'test-pass',
    });

    const sessionData = Buffer.from('data');

    await store3.saveSession('user3', 'alice', sessionData);
    await store3.saveSession('user3', 'bob', sessionData);
    await store3.saveSession('user3', 'charlie', sessionData);
    await store3.saveSession('user3', 'dave@example.com', sessionData);

    const sessions = await store3.listSessions('user3');
    assert.strictEqual(sessions.length, 4, '4 sessions listed');
    assert.ok(sessions.includes('alice'), 'alice in list');
    assert.ok(sessions.includes('bob'), 'bob in list');
    assert.ok(sessions.includes('charlie'), 'charlie in list');
    // Special characters sanitized
    assert.ok(sessions.some(s => s.includes('dave')), 'dave@example.com sanitized');
  });

  await t.test('should handle special characters in userIds and peerIds', async () => {
    const sessionData = Buffer.from('data');

    const ids = [
      { user: 'alice@example.com', peer: 'bob@example.co.uk' },
      { user: 'user/name', peer: 'peer\\name' },
      { user: 'user+tag', peer: 'peer-tag' },
    ];

    for (const { user, peer } of ids) {
      await store.saveSession(user, peer, sessionData);
      const loaded = await store.loadSession(user, peer);
      assert.deepStrictEqual(loaded, sessionData, `Session preserved for ${user} ↔ ${peer}`);
    }
  });

  await t.test('should return empty list for user with no sessions', async () => {
    const sessions = await store.listSessions('user-with-no-sessions');
    assert.strictEqual(sessions.length, 0, 'Empty list for new user');
  });
});
