/**
 * The single platform-dependent piece of the library.
 *
 * Web, Node 20+, Deno, Bun and Workers all expose `globalThis.crypto`.
 * React Native does not — the app must import `react-native-get-random-values`
 * once, at the top of index.js, which installs the same global.
 *
 * There is intentionally no Math.random() fallback. Shipping a silent downgrade
 * to a non-cryptographic RNG is worse than failing loudly.
 */

import { CryptoUnavailableError } from './errors.js';

// getRandomValues rejects requests larger than 64 KiB, so large draws are chunked.
const MAX_BYTES_PER_CALL = 65536;

const SETUP_HINT =
  'No cryptographically secure random number generator was found.\n' +
  '  React Native: npm i react-native-get-random-values, then add\n' +
  "      import 'react-native-get-random-values';\n" +
  '    as the FIRST line of your index.js (above every other import).\n' +
  '  Node: requires Node 19+ (or run with --experimental-global-webcrypto).\n' +
  '  Browser: requires a secure context (https:// or localhost).';

function getCryptoObject(): Crypto | undefined {
  const g = globalThis as { crypto?: Crypto };
  return g.crypto && typeof g.crypto.getRandomValues === 'function' ? g.crypto : undefined;
}

/** True if this environment can generate secure random bytes. */
export function isCryptoAvailable(): boolean {
  return getCryptoObject() !== undefined;
}

/**
 * Throw a setup-hint error if the environment has no secure RNG.
 * Call this at app startup to fail at boot rather than at first encrypt.
 */
export function assertCryptoAvailable(): void {
  if (!isCryptoAvailable()) throw new CryptoUnavailableError(SETUP_HINT);
}

/** Generate `length` cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0) {
    throw new CryptoUnavailableError('randomBytes length must be a non-negative integer.');
  }
  const cryptoObj = getCryptoObject();
  if (!cryptoObj) throw new CryptoUnavailableError(SETUP_HINT);

  const out = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += MAX_BYTES_PER_CALL) {
    cryptoObj.getRandomValues(out.subarray(offset, Math.min(offset + MAX_BYTES_PER_CALL, length)));
  }
  return out;
}
