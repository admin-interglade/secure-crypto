/**
 * Authenticated encryption. Both algorithms are AEAD: they detect any change to
 * the ciphertext or the associated data, so there is no separate MAC step and no
 * "encrypt-then-forget-to-authenticate" footgun.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { gcm } from '@noble/ciphers/aes.js';
import { DecryptionFailedError, InvalidArgumentError } from './errors.js';

export const ALG_XCHACHA20_POLY1305 = 1;
export const ALG_AES_256_GCM = 2;

export type AlgorithmName = 'xchacha20-poly1305' | 'aes-256-gcm';

export const KEY_LENGTH = 32;

const ALGORITHMS = {
  'xchacha20-poly1305': { id: ALG_XCHACHA20_POLY1305, nonceLength: 24 },
  'aes-256-gcm': { id: ALG_AES_256_GCM, nonceLength: 12 },
} as const;

const BY_ID: Record<number, AlgorithmName> = {
  [ALG_XCHACHA20_POLY1305]: 'xchacha20-poly1305',
  [ALG_AES_256_GCM]: 'aes-256-gcm',
};

/**
 * XChaCha20-Poly1305 is the default: its 24-byte nonce is large enough that
 * random generation never realistically collides, and it is fast in pure JS on
 * devices without AES hardware acceleration.
 */
export const DEFAULT_ALGORITHM: AlgorithmName = 'xchacha20-poly1305';

export function algorithmId(name: AlgorithmName): number {
  const spec = ALGORITHMS[name];
  if (!spec) {
    throw new InvalidArgumentError(
      `Unknown algorithm "${name}". Expected one of: ${Object.keys(ALGORITHMS).join(', ')}.`
    );
  }
  return spec.id;
}

export function algorithmName(id: number): AlgorithmName {
  const name = BY_ID[id];
  if (!name) throw new InvalidArgumentError(`Unknown algorithm id ${id}.`);
  return name;
}

export function nonceLength(name: AlgorithmName): number {
  return ALGORITHMS[name].nonceLength;
}

function cipherFor(name: AlgorithmName, key: Uint8Array, nonce: Uint8Array, aad: Uint8Array) {
  return name === 'aes-256-gcm' ? gcm(key, nonce, aad) : xchacha20poly1305(key, nonce, aad);
}

export function assertKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array)) throw new InvalidArgumentError('Key must be a Uint8Array.');
  if (key.length !== KEY_LENGTH) {
    throw new InvalidArgumentError(`Key must be exactly ${KEY_LENGTH} bytes, got ${key.length}.`);
  }
}

export function aeadEncrypt(
  name: AlgorithmName,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array
): Uint8Array {
  assertKey(key);
  return cipherFor(name, key, nonce, aad).encrypt(plaintext);
}

export function aeadDecrypt(
  name: AlgorithmName,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array {
  assertKey(key);
  try {
    return cipherFor(name, key, nonce, aad).decrypt(ciphertext);
  } catch {
    // Collapse every underlying failure into one opaque error on purpose:
    // distinguishing "bad tag" from "bad padding" is how oracle attacks start.
    throw new DecryptionFailedError();
  }
}
