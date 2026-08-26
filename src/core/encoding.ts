/**
 * Byte/string conversions implemented in pure JS.
 *
 * Deliberately avoids TextEncoder, TextDecoder, Buffer, btoa and atob: none of
 * them are guaranteed present on Hermes, so relying on them is the usual reason
 * a "universal" crypto library fails only on Android.
 */

import { InvalidArgumentError } from './errors.js';

const B64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const B64URL_LOOKUP = /*#__PURE__*/ (() => {
  const table = new Int16Array(256).fill(-1);
  for (let i = 0; i < B64URL_ALPHABET.length; i++) table[B64URL_ALPHABET.charCodeAt(i)] = i;
  // Accept standard base64 characters on input too, so envelopes survive a
  // round-trip through systems that re-encode them.
  table['+'.charCodeAt(0)] = 62;
  table['/'.charCodeAt(0)] = 63;
  return table;
})();

/** Encode a JS string as UTF-8 bytes. */
export function utf8ToBytes(str: string): Uint8Array {
  if (typeof str !== 'string') throw new InvalidArgumentError('Expected a string.');
  const out: number[] = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
      const next = str.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = ((code - 0xd800) << 10) + (next - 0xdc00) + 0x10000;
        i++;
      }
    }
    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f)
      );
    }
  }
  return new Uint8Array(out);
}

/** Decode UTF-8 bytes back into a JS string. */
export function bytesToUtf8(bytes: Uint8Array): string {
  let result = '';
  let i = 0;
  // Build in chunks so very large payloads do not blow the argument limit of
  // String.fromCharCode.
  let chunk: number[] = [];
  while (i < bytes.length) {
    const b0 = bytes[i++];
    let code: number;
    if (b0 < 0x80) {
      code = b0;
    } else if ((b0 & 0xe0) === 0xc0) {
      code = ((b0 & 0x1f) << 6) | (bytes[i++] & 0x3f);
    } else if ((b0 & 0xf0) === 0xe0) {
      code = ((b0 & 0x0f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f);
    } else {
      code =
        ((b0 & 0x07) << 18) |
        ((bytes[i++] & 0x3f) << 12) |
        ((bytes[i++] & 0x3f) << 6) |
        (bytes[i++] & 0x3f);
    }
    if (code > 0xffff) {
      code -= 0x10000;
      chunk.push(0xd800 + (code >> 10), 0xdc00 + (code & 0x3ff));
    } else {
      chunk.push(code);
    }
    if (chunk.length >= 4096) {
      result += String.fromCharCode.apply(null, chunk as unknown as number[]);
      chunk = [];
    }
  }
  if (chunk.length) result += String.fromCharCode.apply(null, chunk as unknown as number[]);
  return result;
}

/** Encode bytes as unpadded base64url (URL-safe, no `=`). */
export function base64UrlEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      B64URL_ALPHABET[(n >> 18) & 63] +
      B64URL_ALPHABET[(n >> 12) & 63] +
      B64URL_ALPHABET[(n >> 6) & 63] +
      B64URL_ALPHABET[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += B64URL_ALPHABET[(n >> 18) & 63] + B64URL_ALPHABET[(n >> 12) & 63];
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out +=
      B64URL_ALPHABET[(n >> 18) & 63] +
      B64URL_ALPHABET[(n >> 12) & 63] +
      B64URL_ALPHABET[(n >> 6) & 63];
  }
  return out;
}

/** Decode base64url (padding optional; standard base64 also accepted). */
export function base64UrlDecode(str: string): Uint8Array {
  let end = str.length;
  while (end > 0 && str.charCodeAt(end - 1) === 61 /* '=' */) end--;

  const fullGroups = Math.floor(end / 4);
  const rest = end - fullGroups * 4;
  if (rest === 1) throw new InvalidArgumentError('Invalid base64url: truncated.');
  const outLen = fullGroups * 3 + (rest === 2 ? 1 : rest === 3 ? 2 : 0);
  const out = new Uint8Array(outLen);

  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < end; i++) {
    const v = B64URL_LOOKUP[str.charCodeAt(i) & 0xff];
    if (v < 0) throw new InvalidArgumentError('Invalid base64url character.');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

/** Hex-encode bytes (lowercase). Handy for test vectors and debugging. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/** Parse a lowercase or uppercase hex string into bytes. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new InvalidArgumentError('Hex string must have even length.');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new InvalidArgumentError('Invalid hex string.');
    out[i] = byte;
  }
  return out;
}

/** Concatenate byte arrays into one. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/** Constant-time byte comparison. Does not early-return on the first difference. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Best-effort wipe of a key buffer. */
export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}

/** Coerce a string-or-bytes argument into bytes. */
export function toBytes(input: string | Uint8Array, label: string): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (typeof input === 'string') return utf8ToBytes(input);
  throw new InvalidArgumentError(`${label} must be a string or Uint8Array.`);
}
