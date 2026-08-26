/**
 * React Native keystore tests.
 *
 * `react-native-keychain` is a native module and cannot run under Node, so the
 * module boundary is faked: a fake keychain records exactly what the library
 * asks the OS to do. That is the part worth testing — whether we request
 * device-only accessibility, isolate services per key, and degrade correctly
 * when the native module is missing or a biometric prompt is cancelled.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { bytesToHex } from '../src/core/encoding.js';
import { generateKey } from '../src/index.js';
import * as keystore from '../src/keystore/index.native.js';

interface StoredEntry {
  username: string;
  password: string;
  options: Record<string, unknown>;
}

function createFakeKeychain(behaviour: { failGet?: boolean } = {}) {
  const entries = new Map<string, StoredEntry>();
  return {
    entries,
    ACCESSIBLE: { WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'AccessibleWhenUnlockedThisDeviceOnly' },
    ACCESS_CONTROL: {
      BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE: 'BiometryCurrentSetOrDevicePasscode',
    },
    async setGenericPassword(username: string, password: string, options: any) {
      entries.set(options.service, { username, password, options });
      return true;
    },
    async getGenericPassword(options: any) {
      if (behaviour.failGet) throw new Error('User canceled the biometric prompt');
      const entry = entries.get(options.service);
      return entry ? { username: entry.username, password: entry.password } : false;
    },
    async resetGenericPassword(options: any) {
      return entries.delete(options.service);
    },
  };
}

/**
 * Point the module at a fake keychain. Passing null restores normal resolution,
 * which under Node fails exactly as it would in an app that forgot to install
 * the native module.
 */
async function loadKeystore(keychain: unknown | null) {
  keystore.__setKeychainForTesting(keychain);
  return keystore;
}

afterEach(() => {
  // Always restore real module resolution between tests.
  keystore.__setKeychainForTesting(null);
  vi.unstubAllGlobals();
});

describe('react native keystore', () => {
  let keychain: ReturnType<typeof createFakeKeychain>;

  beforeEach(() => {
    keychain = createFakeKeychain();
  });

  it('reports its backend and availability', async () => {
    const keystore = await loadKeystore(keychain);
    expect(keystore.backend).toBe('react-native-keychain');
    expect(keystore.isKeystoreAvailable()).toBe(true);
  });

  it('stores and reads a key back', async () => {
    const keystore = await loadKeystore(keychain);
    const key = generateKey();
    await keystore.setKey('session', key);
    expect(bytesToHex((await keystore.getKey('session'))!)).toBe(bytesToHex(key));
  });

  it('returns null for a key that was never stored', async () => {
    const keystore = await loadKeystore(keychain);
    expect(await keystore.getKey('absent')).toBeNull();
    expect(await keystore.hasKey('absent')).toBe(false);
  });

  it('requests device-only accessibility', async () => {
    const keystore = await loadKeystore(keychain);
    await keystore.setKey('session', generateKey());
    const entry = [...keychain.entries.values()][0];
    expect(entry.options.accessible).toBe('AccessibleWhenUnlockedThisDeviceOnly');
  });

  it('gives every key its own keychain service', async () => {
    const keystore = await loadKeystore(keychain);
    await keystore.setKey('alpha', generateKey());
    await keystore.setKey('beta', generateKey());
    expect([...keychain.entries.keys()]).toEqual([
      'com.interglade.securecrypto.default.alpha',
      'com.interglade.securecrypto.default.beta',
    ]);
  });

  it('isolates namespaces', async () => {
    const keystore = await loadKeystore(keychain);
    const appA = generateKey();
    const appB = generateKey();
    await keystore.setKey('shared', appA, { namespace: 'app-a' });
    await keystore.setKey('shared', appB, { namespace: 'app-b' });

    expect(bytesToHex((await keystore.getKey('shared', { namespace: 'app-a' }))!)).toBe(
      bytesToHex(appA)
    );
    expect(await keystore.getKey('shared')).toBeNull();
  });

  it('deletes, and tolerates deleting a missing key', async () => {
    const keystore = await loadKeystore(keychain);
    await keystore.setKey('temp', generateKey());
    await keystore.deleteKey('temp');
    expect(await keystore.getKey('temp')).toBeNull();
    await expect(keystore.deleteKey('never-existed')).resolves.toBeUndefined();
  });

  it('stores keys as hex, never as raw binary in a password field', async () => {
    const keystore = await loadKeystore(keychain);
    const key = generateKey();
    await keystore.setKey('session', key);
    const entry = [...keychain.entries.values()][0];
    expect(entry.password).toBe(bytesToHex(key));
    expect(entry.password).toMatch(/^[0-9a-f]{64}$/);
  });

  describe('getOrCreateKey', () => {
    it('creates once, then returns the same key', async () => {
      const keystore = await loadKeystore(keychain);
      const first = await keystore.getOrCreateKey('device');
      const second = await keystore.getOrCreateKey('device');
      expect(first).toHaveLength(32);
      expect(bytesToHex(second)).toBe(bytesToHex(first));
      expect(keychain.entries.size).toBe(1);
    });
  });

  describe('biometrics', () => {
    it('passes an access control policy and prompt when requested', async () => {
      const keystore = await loadKeystore(keychain);
      await keystore.setKey('protected', generateKey(), {
        requireAuthentication: true,
        authenticationPrompt: 'Unlock your vault',
      });
      const entry = [...keychain.entries.values()][0];
      expect(entry.options.accessControl).toBe('BiometryCurrentSetOrDevicePasscode');
      expect(entry.options.authenticationPrompt).toEqual({ title: 'Unlock your vault' });
    });

    it('returns null when the user cancels the prompt', async () => {
      const cancelling = createFakeKeychain({ failGet: true });
      const keystore = await loadKeystore(cancelling);
      expect(await keystore.getKey('protected', { requireAuthentication: true })).toBeNull();
    });
  });

  describe('missing native module', () => {
    it('reports unavailable instead of throwing', async () => {
      const keystore = await loadKeystore(null);
      expect(keystore.isKeystoreAvailable()).toBe(false);
    });

    it('explains how to install it', async () => {
      const keystore = await loadKeystore(null);
      await expect(keystore.setKey('x', generateKey())).rejects.toThrow(
        /npm install react-native-keychain/
      );
      await expect(keystore.setKey('x', generateKey())).rejects.toThrow(/pod install/);
    });
  });

  describe('validation', () => {
    it('rejects malformed names and empty keys', async () => {
      const keystore = await loadKeystore(keychain);
      await expect(keystore.setKey('has spaces', generateKey())).rejects.toThrow(
        /Invalid key name/
      );
      await expect(keystore.setKey('ok', new Uint8Array(0))).rejects.toThrow(/non-empty/);
    });
  });
});
