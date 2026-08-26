/**
 * Environment tests.
 *
 * Hermes (React Native's JS engine) historically lacks TextEncoder, TextDecoder,
 * Buffer, btoa and atob. Any library that quietly depends on them works in the
 * browser and fails on a device — which is the bug this suite exists to prevent.
 * These tests strip those globals and re-run the full round trip.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  CryptoUnavailableError,
  assertCryptoAvailable,
  decrypt,
  decryptWithPassword,
  encrypt,
  encryptWithPassword,
  generateKey,
  isCryptoAvailable,
  randomBytes,
} from '../src/index.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Hermes-like environment (no TextEncoder / Buffer / btoa)', () => {
  it('encrypts and decrypts without any of them', async () => {
    vi.stubGlobal('TextEncoder', undefined);
    vi.stubGlobal('TextDecoder', undefined);
    vi.stubGlobal('Buffer', undefined);
    vi.stubGlobal('btoa', undefined);
    vi.stubGlobal('atob', undefined);

    const key = generateKey();
    const message = 'works on Hermes 🔐 秘密 café';
    expect(await decrypt(await encrypt(message, key), key)).toBe(message);

    const envelope = await encryptWithPassword(message, 'pw', { iterations: 1000 });
    expect(await decryptWithPassword(envelope, 'pw')).toBe(message);
  });
});

describe('missing CSPRNG', () => {
  it('fails loudly rather than silently downgrading', () => {
    vi.stubGlobal('crypto', undefined);

    expect(isCryptoAvailable()).toBe(false);
    expect(() => assertCryptoAvailable()).toThrow(CryptoUnavailableError);
    expect(() => generateKey()).toThrow(CryptoUnavailableError);
    // The error must tell a React Native developer exactly what to do.
    expect(() => generateKey()).toThrow(/react-native-get-random-values/);
  });

  it('reports availability in a normal environment', () => {
    expect(isCryptoAvailable()).toBe(true);
    expect(() => assertCryptoAvailable()).not.toThrow();
  });
});

describe('randomBytes', () => {
  it('returns the requested length, including past the 64 KiB chunk limit', () => {
    for (const n of [0, 1, 32, 65535, 65536, 70000]) {
      expect(randomBytes(n)).toHaveLength(n);
    }
  });

  it('does not repeat itself', () => {
    const a = randomBytes(32).join(',');
    const b = randomBytes(32).join(',');
    expect(a).not.toBe(b);
  });
});
