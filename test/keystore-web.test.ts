/**
 * Web keystore tests, run against a real IndexedDB implementation and Node's
 * real WebCrypto — so the wrapping key is a genuine non-extractable CryptoKey,
 * not a stub.
 */

import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  KeystoreError,
  backend,
  deleteKey,
  getKey,
  getOrCreateKey,
  hasKey,
  isKeystoreAvailable,
  setKey,
} from '../src/keystore/index.js';
import { decrypt, encrypt, generateKey } from '../src/index.js';
import { bytesToHex } from '../src/core/encoding.js';

beforeEach(() => {
  // Fresh browser profile for every test.
  vi.stubGlobal('indexedDB', new IDBFactory());
});

describe('web keystore', () => {
  it('reports its backend and availability', () => {
    expect(backend).toBe('web-indexeddb');
    expect(isKeystoreAvailable()).toBe(true);
  });

  it('stores and reads a key back', async () => {
    const key = generateKey();
    await setKey('session', key);
    expect(bytesToHex((await getKey('session'))!)).toBe(bytesToHex(key));
  });

  it('returns null for a key that was never stored', async () => {
    expect(await getKey('absent')).toBeNull();
    expect(await hasKey('absent')).toBe(false);
  });

  it('reports presence correctly', async () => {
    await setKey('present', generateKey());
    expect(await hasKey('present')).toBe(true);
  });

  it('overwrites on a second set', async () => {
    const second = generateKey();
    await setKey('rotating', generateKey());
    await setKey('rotating', second);
    expect(bytesToHex((await getKey('rotating'))!)).toBe(bytesToHex(second));
  });

  it('deletes, and tolerates deleting a missing key', async () => {
    await setKey('temp', generateKey());
    await deleteKey('temp');
    expect(await getKey('temp')).toBeNull();
    await expect(deleteKey('never-existed')).resolves.toBeUndefined();
  });

  it('isolates namespaces', async () => {
    const appA = generateKey();
    const appB = generateKey();
    await setKey('shared-name', appA, { namespace: 'app-a' });
    await setKey('shared-name', appB, { namespace: 'app-b' });

    expect(bytesToHex((await getKey('shared-name', { namespace: 'app-a' }))!)).toBe(
      bytesToHex(appA)
    );
    expect(bytesToHex((await getKey('shared-name', { namespace: 'app-b' }))!)).toBe(
      bytesToHex(appB)
    );
    expect(await getKey('shared-name')).toBeNull();
  });

  describe('getOrCreateKey', () => {
    it('creates once, then returns the same key', async () => {
      const first = await getOrCreateKey('device');
      const second = await getOrCreateKey('device');
      expect(first).toHaveLength(32);
      expect(bytesToHex(second)).toBe(bytesToHex(first));
    });

    it('produces a key that actually works for encryption', async () => {
      const key = await getOrCreateKey('device');
      const envelope = await encrypt('persisted secret', key);

      // Simulate a page reload: same database, fresh call.
      const reloaded = await getOrCreateKey('device');
      expect(await decrypt(envelope, reloaded)).toBe('persisted secret');
    });

    it('gives different names different keys', async () => {
      const a = await getOrCreateKey('key-a');
      const b = await getOrCreateKey('key-b');
      expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    });
  });

  describe('at-rest protection', () => {
    it('never writes raw key bytes to storage', async () => {
      const key = generateKey();
      await setKey('secret', key);

      // Read the raw record the way an attacker with the profile directory would.
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open('secure-crypto-keystore', 1);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      const record = await new Promise<any>((resolve, reject) => {
        const request = db.transaction('keys', 'readonly').objectStore('keys').get('default:secret');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });

      const storedHex = bytesToHex(new Uint8Array(record.wrapped));
      expect(storedHex).not.toContain(bytesToHex(key));
      expect(record.wrapped.byteLength).toBe(key.length + 16); // ciphertext + GCM tag
    });

    it('keeps the wrapping key non-extractable', async () => {
      await setKey('anything', generateKey());

      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open('secure-crypto-keystore', 1);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      const record = await new Promise<any>((resolve, reject) => {
        const request = db
          .transaction('keys', 'readonly')
          .objectStore('keys')
          .get('__wrapping-key__');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });

      expect(record.key.extractable).toBe(false);
      // The browser must refuse to hand the material back, even to us.
      await expect(crypto.subtle.exportKey('raw', record.key)).rejects.toThrow();
    });
  });

  describe('validation', () => {
    it('rejects malformed key names and namespaces', async () => {
      await expect(setKey('', generateKey())).rejects.toThrow(KeystoreError);
      await expect(setKey('has spaces', generateKey())).rejects.toThrow(/Invalid key name/);
      await expect(setKey('a/b', generateKey())).rejects.toThrow(/Invalid key name/);
      await expect(setKey('ok', generateKey(), { namespace: 'bad ns' })).rejects.toThrow(
        /Invalid namespace/
      );
    });

    it('rejects an empty key', async () => {
      await expect(setKey('ok', new Uint8Array(0))).rejects.toThrow(/non-empty/);
    });
  });

  describe('unsupported environment', () => {
    it('explains what to do when IndexedDB is missing', async () => {
      vi.stubGlobal('indexedDB', undefined);
      expect(isKeystoreAvailable()).toBe(false);
      await expect(setKey('x', generateKey())).rejects.toThrow(/KMS|secrets manager/);
    });
  });
});
