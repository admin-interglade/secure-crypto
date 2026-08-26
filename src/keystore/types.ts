/**
 * Shared contract for the platform key stores.
 *
 * Both implementations expose exactly these functions, so application code can
 * import `@interglade/secure-crypto/keystore` and never branch on platform.
 */

import { SecureCryptoError } from '../core/errors.js';

/** Raised when the platform has no usable key store, or the store rejects a call. */
export class KeystoreError extends SecureCryptoError {
  constructor(message: string) {
    super(message);
    this.name = 'KeystoreError';
  }
}

export interface KeystoreOptions {
  /**
   * Isolates one app's keys from another's on the same origin or device.
   * Defaults to `'default'`.
   */
  namespace?: string;
  /**
   * React Native only. Require the device biometric or passcode before the key
   * can be read. Ignored on the web, where the browser offers no equivalent.
   */
  requireAuthentication?: boolean;
  /**
   * React Native only. Prompt shown when `requireAuthentication` is set.
   */
  authenticationPrompt?: string;
}

export interface KeystoreApi {
  /** Which platform mechanism is backing this build. */
  readonly backend: 'web-indexeddb' | 'react-native-keychain';
  isKeystoreAvailable(): boolean;
  setKey(name: string, key: Uint8Array, options?: KeystoreOptions): Promise<void>;
  getKey(name: string, options?: KeystoreOptions): Promise<Uint8Array | null>;
  hasKey(name: string, options?: KeystoreOptions): Promise<boolean>;
  deleteKey(name: string, options?: KeystoreOptions): Promise<void>;
  getOrCreateKey(name: string, options?: KeystoreOptions): Promise<Uint8Array>;
}

/** Validate a key name: used to build storage identifiers, so keep it boring. */
export function assertName(name: string): void {
  if (typeof name !== 'string' || name.length === 0) {
    throw new KeystoreError('Key name must be a non-empty string.');
  }
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(name)) {
    throw new KeystoreError(
      `Invalid key name ${JSON.stringify(name)}. Use 1-128 characters from A-Z a-z 0-9 . _ -`
    );
  }
}

export function namespaceOf(options?: KeystoreOptions): string {
  const namespace = options?.namespace ?? 'default';
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(namespace)) {
    throw new KeystoreError(
      `Invalid namespace ${JSON.stringify(namespace)}. Use 1-64 characters from A-Z a-z 0-9 . _ -`
    );
  }
  return namespace;
}

export function assertKeyBytes(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length === 0) {
    throw new KeystoreError('Key must be a non-empty Uint8Array.');
  }
}
