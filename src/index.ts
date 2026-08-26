/**
 * @interglade/secure-crypto
 *
 * One encryption API for React Native, the browser and Node. Same code, same
 * bytes: an envelope produced on a phone decrypts on your server and vice versa.
 */

import {
  DEFAULT_ALGORITHM,
  KEY_LENGTH,
  aeadDecrypt,
  aeadEncrypt,
  algorithmId,
  algorithmName,
  assertKey,
  nonceLength,
  type AlgorithmName,
} from './core/aead.js';
import {
  KDF_NONE,
  SALT_LENGTH,
  deriveKeyWith,
  kdfDisplayName,
  packKdfParams,
  resolveKdf,
  type KdfOptions,
} from './core/kdf.js';
import {
  ENVELOPE_PREFIX,
  FORMAT_VERSION,
  buildAad,
  buildHeader,
  envelopeKdf,
  packEnvelope,
  parseEnvelope,
} from './core/envelope.js';
import { bytesToUtf8, toBytes } from './core/encoding.js';
import { randomBytes } from './core/random.js';
import { InvalidArgumentError } from './core/errors.js';

const EMPTY = new Uint8Array(0);

export interface EncryptOptions {
  /** Cipher to use. Defaults to `xchacha20-poly1305`. */
  algorithm?: AlgorithmName;
  /**
   * Additional authenticated data. Not encrypted, but bound to the ciphertext:
   * decryption fails unless the exact same value is supplied. Use it to pin a
   * record to its context — `aad: userId` stops a valid envelope from being
   * replayed against a different account's row.
   */
  aad?: string | Uint8Array;
}

export type DecryptOptions = Pick<EncryptOptions, 'aad'>;

export type EncryptWithPasswordOptions = EncryptOptions & KdfOptions;

/** Non-secret metadata read back out of an envelope. */
export interface EnvelopeInfo {
  version: number;
  algorithm: AlgorithmName;
  kdf: string;
  iterations?: number;
  scrypt?: { logN: number; r: number; p: number };
  saltLength: number;
  nonceLength: number;
  ciphertextLength: number;
}

/** Generate a fresh 32-byte key from the platform CSPRNG. */
export function generateKey(): Uint8Array {
  return randomBytes(KEY_LENGTH);
}

/** Generate a random salt suitable for `deriveKey`. */
export function generateSalt(length: number = SALT_LENGTH): Uint8Array {
  return randomBytes(length);
}

/**
 * Encrypt with a 32-byte key. Returns a self-describing envelope string that is
 * safe to store in a database, a cookie, or a URL.
 */
export async function encrypt(
  data: string | Uint8Array,
  key: Uint8Array,
  options: EncryptOptions = {}
): Promise<string> {
  assertKey(key);
  const algorithm = options.algorithm ?? DEFAULT_ALGORITHM;
  const plaintext = toBytes(data, 'data');
  const userAad = options.aad === undefined ? EMPTY : toBytes(options.aad, 'aad');

  const nonce = randomBytes(nonceLength(algorithm));
  const header = buildHeader({
    algId: algorithmId(algorithm),
    kdfId: KDF_NONE,
    kdfParams: new Uint8Array(4),
    saltLength: 0,
    nonceLength: nonce.length,
  });

  const ciphertext = aeadEncrypt(algorithm, key, nonce, buildAad(header, userAad), plaintext);
  return packEnvelope(header, EMPTY, nonce, ciphertext);
}

/** Decrypt an envelope produced by `encrypt`, returning the plaintext as a UTF-8 string. */
export async function decrypt(
  envelope: string,
  key: Uint8Array,
  options: DecryptOptions = {}
): Promise<string> {
  return bytesToUtf8(await decryptToBytes(envelope, key, options));
}

/** Decrypt an envelope, returning raw bytes. Use for binary payloads. */
export async function decryptToBytes(
  envelope: string,
  key: Uint8Array,
  options: DecryptOptions = {}
): Promise<Uint8Array> {
  assertKey(key);
  const parts = parseEnvelope(envelope);
  const algorithm = algorithmName(parts.algId);
  const userAad = options.aad === undefined ? EMPTY : toBytes(options.aad, 'aad');
  return aeadDecrypt(
    algorithm,
    key,
    parts.nonce,
    buildAad(parts.header, userAad),
    parts.ciphertext
  );
}

/**
 * Encrypt with a password. A random salt is generated per call and the KDF
 * settings are recorded in the envelope, so `decryptWithPassword` needs nothing
 * but the password.
 *
 * This is deliberately slow (hundreds of milliseconds). For many records, call
 * `deriveKey` once and use `encrypt` with the resulting key.
 */
export async function encryptWithPassword(
  data: string | Uint8Array,
  password: string | Uint8Array,
  options: EncryptWithPasswordOptions = {}
): Promise<string> {
  const algorithm = options.algorithm ?? DEFAULT_ALGORITHM;
  const kdf = resolveKdf(options as KdfOptions);
  const plaintext = toBytes(data, 'data');
  const userAad = options.aad === undefined ? EMPTY : toBytes(options.aad, 'aad');

  const salt = randomBytes(SALT_LENGTH);
  const nonce = randomBytes(nonceLength(algorithm));
  const header = buildHeader({
    algId: algorithmId(algorithm),
    kdfId: kdf.kdfId,
    kdfParams: packKdfParams(kdf),
    saltLength: salt.length,
    nonceLength: nonce.length,
  });

  const key = await deriveKeyWith(password, salt, kdf);
  try {
    const ciphertext = aeadEncrypt(algorithm, key, nonce, buildAad(header, userAad), plaintext);
    return packEnvelope(header, salt, nonce, ciphertext);
  } finally {
    key.fill(0);
  }
}

/** Decrypt a password-protected envelope, returning a UTF-8 string. */
export async function decryptWithPassword(
  envelope: string,
  password: string | Uint8Array,
  options: DecryptOptions = {}
): Promise<string> {
  return bytesToUtf8(await decryptWithPasswordToBytes(envelope, password, options));
}

/** Decrypt a password-protected envelope, returning raw bytes. */
export async function decryptWithPasswordToBytes(
  envelope: string,
  password: string | Uint8Array,
  options: DecryptOptions = {}
): Promise<Uint8Array> {
  const parts = parseEnvelope(envelope);
  const kdf = envelopeKdf(parts);
  if (!kdf) {
    throw new InvalidArgumentError(
      'This envelope was encrypted with a raw key, not a password. Use decrypt() instead.'
    );
  }
  const algorithm = algorithmName(parts.algId);
  const userAad = options.aad === undefined ? EMPTY : toBytes(options.aad, 'aad');

  const key = await deriveKeyWith(password, parts.salt, kdf);
  try {
    return aeadDecrypt(
      algorithm,
      key,
      parts.nonce,
      buildAad(parts.header, userAad),
      parts.ciphertext
    );
  } finally {
    key.fill(0);
  }
}

/**
 * Stretch a password into a reusable 32-byte key.
 *
 * Store the salt (it is not secret) alongside the account and pass the same salt
 * every time, or the derived key will differ.
 */
export async function deriveKey(
  password: string | Uint8Array,
  salt: Uint8Array,
  options: KdfOptions = {}
): Promise<Uint8Array> {
  if (!(salt instanceof Uint8Array)) {
    throw new InvalidArgumentError('Salt must be a Uint8Array — use generateSalt().');
  }
  return deriveKeyWith(password, salt, resolveKdf(options));
}

/** True if `value` looks like an envelope this library produced. */
export function isEnvelope(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith(ENVELOPE_PREFIX);
}

/** Read an envelope's non-secret metadata without decrypting it. */
export function inspect(envelope: string): EnvelopeInfo {
  const parts = parseEnvelope(envelope);
  const kdf = envelopeKdf(parts);
  const info: EnvelopeInfo = {
    version: parts.version,
    algorithm: algorithmName(parts.algId),
    kdf: kdfDisplayName(parts.kdfId),
    saltLength: parts.salt.length,
    nonceLength: parts.nonce.length,
    ciphertextLength: parts.ciphertext.length,
  };
  if (kdf && 'iterations' in kdf) info.iterations = kdf.iterations;
  if (kdf && 'logN' in kdf) info.scrypt = { logN: kdf.logN, r: kdf.r, p: kdf.p };
  return info;
}

export { FORMAT_VERSION, KEY_LENGTH, SALT_LENGTH, DEFAULT_ALGORITHM };
export { DEFAULT_PBKDF2_ITERATIONS, DEFAULT_SCRYPT_PARAMS } from './core/kdf.js';
export { isCryptoAvailable, assertCryptoAvailable, randomBytes } from './core/random.js';
export {
  base64UrlDecode,
  base64UrlEncode,
  bytesToHex,
  bytesToUtf8,
  hexToBytes,
  utf8ToBytes,
  wipe,
} from './core/encoding.js';
export {
  SecureCryptoError,
  CryptoUnavailableError,
  DecryptionFailedError,
  InvalidArgumentError,
  InvalidEnvelopeError,
  UnsupportedVersionError,
} from './core/errors.js';
export type { AlgorithmName, KdfOptions };
