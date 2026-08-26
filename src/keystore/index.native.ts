/**
 * React Native key store — iOS Keychain and Android Keystore.
 *
 * Keys are held by the operating system, encrypted with hardware-backed key
 * material (Secure Enclave / TEE / StrongBox where available). They survive app
 * restarts, are not included in `AsyncStorage` dumps, and — with
 * `WHEN_UNLOCKED_THIS_DEVICE_ONLY` — do not migrate to a restored backup or a
 * new device.
 *
 * `react-native-keychain` is an optional peer dependency, loaded lazily so that
 * importing this module never crashes an app that does not use the keystore.
 */

import { bytesToHex, hexToBytes } from '../core/encoding.js';
import { randomBytes } from '../core/random.js';
import {
  KeystoreError,
  assertKeyBytes,
  assertName,
  namespaceOf,
  type KeystoreOptions,
} from './types.js';

export const backend = 'react-native-keychain' as const;

// Metro/CommonJS provides this. It is declared here because the package builds
// with no ambient Node types, and the React Native export condition resolves to
// the CJS bundle, where `require` is real.
declare const require: (id: string) => unknown;

interface KeychainCredentials {
  username: string;
  password: string;
}

interface KeychainModule {
  setGenericPassword(
    username: string,
    password: string,
    options?: Record<string, unknown>
  ): Promise<unknown>;
  getGenericPassword(options?: Record<string, unknown>): Promise<false | KeychainCredentials>;
  resetGenericPassword(options?: Record<string, unknown>): Promise<boolean>;
  ACCESSIBLE?: Record<string, string>;
  ACCESS_CONTROL?: Record<string, string>;
  AUTHENTICATION_TYPE?: Record<string, string>;
}

const MISSING_MODULE =
  'react-native-keychain is required by @interglade/secure-crypto/keystore.\n' +
  '  npm install react-native-keychain\n' +
  '  cd ios && pod install\n' +
  'Then rebuild the app — this is a native module, so a Metro reload is not enough.';

let cached: KeychainModule | null = null;

/**
 * Test seam. `react-native-keychain` is a native module and cannot load under
 * Node, so the suite substitutes a fake that records what the library asks the
 * OS to do. Pass `null` to restore normal resolution.
 *
 * @internal Not part of the supported API; may change without a major version.
 */
export function __setKeychainForTesting(mod: unknown): void {
  cached = (mod as KeychainModule | null) ?? null;
}

function loadKeychain(): KeychainModule {
  if (cached) return cached;
  try {
    // Resolved at call time so the import never breaks apps that skip the keystore.
    const mod = require('react-native-keychain') as KeychainModule & { default?: KeychainModule };
    cached = (mod.default ?? mod) as KeychainModule;
  } catch {
    throw new KeystoreError(MISSING_MODULE);
  }
  if (typeof cached?.setGenericPassword !== 'function') {
    throw new KeystoreError(MISSING_MODULE);
  }
  return cached;
}

/** True if the native keychain module is installed and linked. Never throws. */
export function isKeystoreAvailable(): boolean {
  try {
    loadKeychain();
    return true;
  } catch {
    return false;
  }
}

/** One keychain service entry per stored key, so deletes are independent. */
function serviceFor(namespace: string, name: string): string {
  return `com.interglade.securecrypto.${namespace}.${name}`;
}

function accessOptions(keychain: KeychainModule, options?: KeystoreOptions) {
  const result: Record<string, unknown> = {
    // Not readable while the device is locked, and never restored onto a
    // different device from a backup.
    accessible: keychain.ACCESSIBLE?.WHEN_UNLOCKED_THIS_DEVICE_ONLY ?? undefined,
  };
  if (options?.requireAuthentication) {
    result.accessControl = keychain.ACCESS_CONTROL?.BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE;
    result.authenticationPrompt = {
      title: options.authenticationPrompt ?? 'Unlock to access your encryption key',
    };
  }
  return result;
}

/** Store a key. Overwrites any existing key with the same name. */
export async function setKey(
  name: string,
  key: Uint8Array,
  options?: KeystoreOptions
): Promise<void> {
  assertName(name);
  assertKeyBytes(key);
  const namespace = namespaceOf(options);
  const keychain = loadKeychain();

  try {
    await keychain.setGenericPassword(name, bytesToHex(key), {
      service: serviceFor(namespace, name),
      ...accessOptions(keychain, options),
    });
  } catch (error) {
    throw new KeystoreError(
      `Could not store key "${name}" in the device keychain: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
}

/**
 * Read a key back, or null if it was never stored.
 *
 * With `requireAuthentication`, a cancelled biometric prompt also returns null:
 * the platform reports refusal and absence the same way.
 */
export async function getKey(
  name: string,
  options?: KeystoreOptions
): Promise<Uint8Array | null> {
  assertName(name);
  const namespace = namespaceOf(options);
  const keychain = loadKeychain();

  let credentials: false | KeychainCredentials;
  try {
    credentials = await keychain.getGenericPassword({
      service: serviceFor(namespace, name),
      ...accessOptions(keychain, options),
    });
  } catch {
    // A cancelled or failed biometric prompt lands here.
    return null;
  }
  if (!credentials || !credentials.password) return null;

  try {
    return hexToBytes(credentials.password);
  } catch {
    throw new KeystoreError(
      `Stored key "${name}" is corrupt and could not be decoded. Delete it and create a new one.`
    );
  }
}

export async function hasKey(name: string, options?: KeystoreOptions): Promise<boolean> {
  return (await getKey(name, options)) !== null;
}

/** Delete a key. Deleting one that does not exist is not an error. */
export async function deleteKey(name: string, options?: KeystoreOptions): Promise<void> {
  assertName(name);
  const namespace = namespaceOf(options);
  const keychain = loadKeychain();
  try {
    await keychain.resetGenericPassword({ service: serviceFor(namespace, name) });
  } catch (error) {
    throw new KeystoreError(
      `Could not delete key "${name}": ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Read a key, generating and storing a fresh one on first call.
 *
 * This is the usual entry point: it gives a device a stable 32-byte key that
 * survives app restarts and lives in hardware-backed storage.
 */
export async function getOrCreateKey(
  name: string,
  options?: KeystoreOptions
): Promise<Uint8Array> {
  const existing = await getKey(name, options);
  if (existing) return existing;

  const key = randomBytes(32);
  await setKey(name, key, options);
  return key;
}

export { KeystoreError } from './types.js';
export type { KeystoreOptions, KeystoreApi } from './types.js';
