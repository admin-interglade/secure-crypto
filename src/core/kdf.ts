/**
 * Password-based key derivation.
 *
 * A password is not a key. These functions stretch one into 32 bytes slowly
 * enough that offline guessing is expensive. The cost is intentional — derive
 * once at login and reuse the key, do not call this per record.
 */

import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { InvalidArgumentError } from './errors.js';
import { toBytes } from './encoding.js';
import { KEY_LENGTH } from './aead.js';

export const KDF_NONE = 0;
export const KDF_PBKDF2_SHA256 = 1;
export const KDF_SCRYPT = 2;

export type KdfName = 'pbkdf2' | 'scrypt';

/** OWASP's 2023+ floor for PBKDF2-HMAC-SHA256. */
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;

/** N = 2^15 = 32768, r = 8, p = 1 — about 32 MB of memory, tolerable on phones. */
export const DEFAULT_SCRYPT_PARAMS = { logN: 15, r: 8, p: 1 } as const;

export const SALT_LENGTH = 16;

export interface Pbkdf2Options {
  kdf?: 'pbkdf2';
  /** Iteration count. Higher is slower and stronger. */
  iterations?: number;
}

export interface ScryptOptions {
  kdf: 'scrypt';
  /** log2 of the CPU/memory cost N. 15 means N = 32768. */
  logN?: number;
  /** Block size. */
  r?: number;
  /** Parallelism. */
  p?: number;
}

export type KdfOptions = Pbkdf2Options | ScryptOptions;

/** The KDF settings actually used, as recorded in (and recovered from) an envelope. */
export type ResolvedKdf =
  | { kdfId: typeof KDF_PBKDF2_SHA256; iterations: number }
  | { kdfId: typeof KDF_SCRYPT; logN: number; r: number; p: number };

export function resolveKdf(options: KdfOptions = {}): ResolvedKdf {
  if (options.kdf === 'scrypt') {
    const logN = options.logN ?? DEFAULT_SCRYPT_PARAMS.logN;
    const r = options.r ?? DEFAULT_SCRYPT_PARAMS.r;
    const p = options.p ?? DEFAULT_SCRYPT_PARAMS.p;
    if (logN < 1 || logN > 31) throw new InvalidArgumentError('scrypt logN must be 1..31.');
    if (r < 1 || r > 255) throw new InvalidArgumentError('scrypt r must be 1..255.');
    if (p < 1 || p > 255) throw new InvalidArgumentError('scrypt p must be 1..255.');
    return { kdfId: KDF_SCRYPT, logN, r, p };
  }
  const iterations = (options as Pbkdf2Options).iterations ?? DEFAULT_PBKDF2_ITERATIONS;
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > 0xffffffff) {
    throw new InvalidArgumentError('pbkdf2 iterations must be an integer in 1..4294967295.');
  }
  return { kdfId: KDF_PBKDF2_SHA256, iterations };
}

/** Pack KDF parameters into the fixed 4-byte header slot. */
export function packKdfParams(kdf: ResolvedKdf): Uint8Array {
  const out = new Uint8Array(4);
  if (kdf.kdfId === KDF_PBKDF2_SHA256) {
    const n = kdf.iterations;
    out[0] = (n >>> 24) & 0xff;
    out[1] = (n >>> 16) & 0xff;
    out[2] = (n >>> 8) & 0xff;
    out[3] = n & 0xff;
  } else {
    out[0] = kdf.logN;
    out[1] = kdf.r;
    out[2] = kdf.p;
    out[3] = 0;
  }
  return out;
}

/** Recover KDF parameters from the header slot. */
export function unpackKdfParams(kdfId: number, params: Uint8Array): ResolvedKdf {
  if (kdfId === KDF_PBKDF2_SHA256) {
    const iterations =
      ((params[0] << 24) >>> 0) + (params[1] << 16) + (params[2] << 8) + params[3];
    return { kdfId: KDF_PBKDF2_SHA256, iterations };
  }
  if (kdfId === KDF_SCRYPT) {
    return { kdfId: KDF_SCRYPT, logN: params[0], r: params[1], p: params[2] };
  }
  throw new InvalidArgumentError(`Unknown KDF id ${kdfId}.`);
}

/** Stretch a password into a 32-byte key using the given salt and parameters. */
export async function deriveKeyWith(
  password: string | Uint8Array,
  salt: Uint8Array,
  kdf: ResolvedKdf
): Promise<Uint8Array> {
  const passwordBytes = toBytes(password, 'password');
  if (passwordBytes.length === 0) throw new InvalidArgumentError('Password must not be empty.');
  if (salt.length === 0) throw new InvalidArgumentError('Salt must not be empty.');

  if (kdf.kdfId === KDF_PBKDF2_SHA256) {
    return pbkdf2Async(sha256, passwordBytes, salt, { c: kdf.iterations, dkLen: KEY_LENGTH });
  }
  return scryptAsync(passwordBytes, salt, {
    N: 2 ** kdf.logN,
    r: kdf.r,
    p: kdf.p,
    dkLen: KEY_LENGTH,
  });
}

export function kdfDisplayName(kdfId: number): string {
  if (kdfId === KDF_PBKDF2_SHA256) return 'pbkdf2-sha256';
  if (kdfId === KDF_SCRYPT) return 'scrypt';
  return 'none';
}
