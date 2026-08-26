/**
 * Known-answer tests: the contract that makes this library "universal".
 *
 * Every vector is a fixed key/nonce/plaintext with a frozen expected envelope.
 * Run this exact file under Node (vitest), in a browser, and inside a React
 * Native app — if all three agree, an envelope written on a phone is guaranteed
 * to open on the server.
 *
 * If a change to the library makes one of these fail, the wire format changed.
 * That is a breaking change, not a test to update.
 */

import { describe, expect, it } from 'vitest';
import vectors from './vectors.json' with { type: 'json' };
import { FORMAT_VERSION, decrypt, decryptWithPassword, inspect } from '../src/index.js';
import { hexToBytes } from '../src/core/encoding.js';
import { encryptDeterministic, encryptWithPasswordDeterministic } from './deterministic.js';
import type { AlgorithmName } from '../src/core/aead.js';
import type { KdfOptions } from '../src/core/kdf.js';

it('vector file targets the current format version', () => {
  expect(vectors.formatVersion).toBe(FORMAT_VERSION);
});

describe('key vectors', () => {
  it.each(vectors.keyVectors)('$name', async (vector) => {
    const key = hexToBytes(vector.keyHex);

    // 1. The frozen envelope still decrypts to the expected plaintext.
    expect(await decrypt(vector.envelope, key, { aad: vector.aad })).toBe(vector.plaintext);

    // 2. Re-encrypting the same inputs reproduces the envelope byte for byte.
    const rebuilt = encryptDeterministic({
      plaintext: vector.plaintext,
      key,
      nonce: hexToBytes(vector.nonceHex),
      algorithm: vector.algorithm as AlgorithmName,
      aad: vector.aad,
    });
    expect(rebuilt).toBe(vector.envelope);

    // 3. The envelope self-describes the algorithm it was written with.
    expect(inspect(vector.envelope).algorithm).toBe(vector.algorithm);
  });
});

describe('password vectors', () => {
  it.each(vectors.passwordVectors)('$name', async (vector) => {
    expect(await decryptWithPassword(vector.envelope, vector.password)).toBe(vector.plaintext);

    const rebuilt = await encryptWithPasswordDeterministic({
      plaintext: vector.plaintext,
      password: vector.password,
      salt: hexToBytes(vector.saltHex),
      nonce: hexToBytes(vector.nonceHex),
      algorithm: vector.algorithm as AlgorithmName,
      kdfOptions: vector.kdfOptions as KdfOptions,
    });
    expect(rebuilt).toBe(vector.envelope);
  });
});
