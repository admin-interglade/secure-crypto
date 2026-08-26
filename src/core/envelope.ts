/**
 * The wire format.
 *
 *   "sc1." + base64url( header | salt | nonce | ciphertext‖tag )
 *
 * The 11-byte header is fixed-width and self-describing, so `decrypt` never
 * needs out-of-band parameters — the algorithm, the KDF and its cost settings
 * all travel with the data:
 *
 *   offset  size  meaning
 *   ------  ----  ---------------------------------------------
 *        0     2  magic "SC"
 *        2     1  format version (currently 1)
 *        3     1  algorithm id   (1 = XChaCha20-Poly1305, 2 = AES-256-GCM)
 *        4     1  KDF id         (0 = none/raw key, 1 = PBKDF2-SHA256, 2 = scrypt)
 *        5     4  KDF parameters (iterations, or logN|r|p|0)
 *        9     1  salt length    (0 when no KDF)
 *       10     1  nonce length
 *
 * The whole header is fed to the cipher as associated data, which binds the
 * version and cost parameters to the ciphertext: an attacker cannot rewrite the
 * header to downgrade the algorithm or weaken the KDF without failing the tag
 * check.
 *
 * The version byte is the reason this format can evolve. `decrypt` must keep
 * reading every version it has ever written, forever.
 */

import { InvalidEnvelopeError, UnsupportedVersionError } from './errors.js';
import { base64UrlDecode, base64UrlEncode, concatBytes } from './encoding.js';
import { KDF_NONE, unpackKdfParams, type ResolvedKdf } from './kdf.js';

export const FORMAT_VERSION = 1;
export const ENVELOPE_PREFIX = 'sc1.';
export const HEADER_LENGTH = 11;

const MAGIC_S = 0x53;
const MAGIC_C = 0x43;

export interface EnvelopeParts {
  version: number;
  algId: number;
  kdfId: number;
  kdfParams: Uint8Array;
  salt: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  /** The raw header bytes, reused verbatim as associated data. */
  header: Uint8Array;
}

export function buildHeader(input: {
  algId: number;
  kdfId: number;
  kdfParams: Uint8Array;
  saltLength: number;
  nonceLength: number;
}): Uint8Array {
  const header = new Uint8Array(HEADER_LENGTH);
  header[0] = MAGIC_S;
  header[1] = MAGIC_C;
  header[2] = FORMAT_VERSION;
  header[3] = input.algId;
  header[4] = input.kdfId;
  header.set(input.kdfParams, 5);
  header[9] = input.saltLength;
  header[10] = input.nonceLength;
  return header;
}

/** Build the associated data actually passed to the cipher. */
export function buildAad(header: Uint8Array, userAad: Uint8Array): Uint8Array {
  return userAad.length === 0 ? header : concatBytes(header, userAad);
}

export function packEnvelope(
  header: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array
): string {
  return ENVELOPE_PREFIX + base64UrlEncode(concatBytes(header, salt, nonce, ciphertext));
}

export function parseEnvelope(envelope: string): EnvelopeParts {
  if (typeof envelope !== 'string') {
    throw new InvalidEnvelopeError('Envelope must be a string.');
  }
  const dot = envelope.indexOf('.');
  if (dot < 0 || envelope.slice(0, 3) !== 'sc1') {
    throw new InvalidEnvelopeError(
      'Not a secure-crypto envelope: expected a string starting with "sc1.".'
    );
  }
  if (envelope.slice(0, dot + 1) !== ENVELOPE_PREFIX) {
    throw new UnsupportedVersionError(
      `Envelope format "${envelope.slice(0, dot)}" is newer than this library understands. Upgrade @interglade/secure-crypto.`
    );
  }

  let raw: Uint8Array;
  try {
    raw = base64UrlDecode(envelope.slice(dot + 1));
  } catch {
    throw new InvalidEnvelopeError('Envelope payload is not valid base64url.');
  }

  if (raw.length < HEADER_LENGTH) throw new InvalidEnvelopeError('Envelope is truncated.');
  if (raw[0] !== MAGIC_S || raw[1] !== MAGIC_C) {
    throw new InvalidEnvelopeError('Envelope header magic does not match.');
  }

  const version = raw[2];
  if (version !== FORMAT_VERSION) {
    throw new UnsupportedVersionError(
      `Envelope format version ${version} is not supported by this build.`
    );
  }

  const saltLength = raw[9];
  const nonceLength = raw[10];
  const saltStart = HEADER_LENGTH;
  const nonceStart = saltStart + saltLength;
  const cipherStart = nonceStart + nonceLength;
  if (raw.length <= cipherStart) {
    throw new InvalidEnvelopeError('Envelope is truncated: no ciphertext present.');
  }

  return {
    version,
    algId: raw[3],
    kdfId: raw[4],
    kdfParams: raw.slice(5, 9),
    salt: raw.slice(saltStart, nonceStart),
    nonce: raw.slice(nonceStart, cipherStart),
    ciphertext: raw.slice(cipherStart),
    header: raw.slice(0, HEADER_LENGTH),
  };
}

/** KDF settings recorded in an envelope, or null if it was encrypted with a raw key. */
export function envelopeKdf(parts: EnvelopeParts): ResolvedKdf | null {
  if (parts.kdfId === KDF_NONE) return null;
  return unpackKdfParams(parts.kdfId, parts.kdfParams);
}
