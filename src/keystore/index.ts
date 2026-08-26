/**
 * Web key store — IndexedDB, protected by a non-extractable WebCrypto key.
 *
 * The obvious implementation (put the key bytes in localStorage) means anyone
 * who can read the browser profile directory gets the key. Instead:
 *
 *   1. On first use, generate an AES-GCM wrapping key with `extractable: false`.
 *      The browser stores the key material outside JavaScript's reach — it can
 *      be *used* but never read back, not even by this library.
 *   2. Store only that CryptoKey handle in IndexedDB.
 *   3. Encrypt every application key under it. What lands on disk is ciphertext.
 *
 * So a stolen profile directory yields wrapped bytes and an unusable handle.
 *
 * This does NOT stop an attacker who can execute JavaScript on your origin —
 * XSS can simply call `getKey()`. A Content Security Policy is what defends
 * against that; this defends against offline access to the stored data.
 */

import { randomBytes } from '../core/random.js';
import {
  KeystoreError,
  assertKeyBytes,
  assertName,
  namespaceOf,
  type KeystoreOptions,
} from './types.js';

const DB_NAME = 'secure-crypto-keystore';
const DB_VERSION = 1;
const STORE_NAME = 'keys';
const WRAPPING_KEY_ID = '__wrapping-key__';
const WRAP_IV_LENGTH = 12;

export const backend = 'web-indexeddb' as const;

interface WrappedRecord {
  id: string;
  iv: Uint8Array;
  wrapped: ArrayBuffer;
}

interface WrappingRecord {
  id: string;
  key: CryptoKey;
}

/**
 * WebCrypto's `BufferSource` requires a view over a plain ArrayBuffer, while
 * `Uint8Array` may be backed by a SharedArrayBuffer. Copying into a fresh array
 * satisfies the type and guarantees the bytes are not in shared memory — worth
 * the 12-to-32-byte copy for key material.
 */
function asBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

function subtleOrThrow(): SubtleCrypto {
  const cryptoObj = (globalThis as { crypto?: Crypto }).crypto;
  if (!cryptoObj?.subtle) {
    throw new KeystoreError(
      'WebCrypto (crypto.subtle) is unavailable. It requires a secure context — serve the page over https:// or localhost.'
    );
  }
  return cryptoObj.subtle;
}

function indexedDbOrThrow(): IDBFactory {
  const idb = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
  if (!idb) {
    throw new KeystoreError(
      'IndexedDB is unavailable, so there is nowhere to store a key.\n' +
        '  Server-side (Node): do not use this keystore. Keep keys in a KMS, a secrets manager, or an environment variable.\n' +
        '  React Native: import from "@interglade/secure-crypto/keystore" — the native entry uses the platform keychain.\n' +
        '  Browser: private-mode restrictions or a blocked storage policy can also cause this.'
    );
  }
  return idb;
}

/** True if this environment can store keys. Never throws. */
export function isKeystoreAvailable(): boolean {
  const g = globalThis as { crypto?: Crypto; indexedDB?: IDBFactory };
  return Boolean(g.indexedDB && g.crypto?.subtle);
}

function promisify<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new KeystoreError(request.error?.message ?? 'IndexedDB error.'));
  });
}

function openDatabase(): Promise<IDBDatabase> {
  const idb = indexedDbOrThrow();
  return new Promise((resolve, reject) => {
    const request = idb.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(new KeystoreError(request.error?.message ?? 'Could not open the keystore database.'));
    request.onblocked = () =>
      reject(new KeystoreError('The keystore database is blocked by another open tab.'));
  });
}

async function withStore<T>(
  mode: IDBTransactionMode,
  fn: (store: IDBObjectStore) => Promise<T> | T
): Promise<T> {
  const db = await openDatabase();
  try {
    const transaction = db.transaction(STORE_NAME, mode);
    const result = await fn(transaction.objectStore(STORE_NAME));
    await new Promise<void>((resolve, reject) => {
      transaction.oncomplete = () => resolve();
      transaction.onabort = transaction.onerror = () =>
        reject(new KeystoreError(transaction.error?.message ?? 'Keystore transaction failed.'));
    });
    return result;
  } finally {
    db.close();
  }
}

function recordId(namespace: string, name: string): string {
  return `${namespace}:${name}`;
}

/**
 * Fetch the wrapping key, creating it on first use.
 *
 * `extractable: false` is the entire point — do not "helpfully" flip it to make
 * debugging easier, or the stored keys stop being protected at rest.
 */
async function getWrappingKey(): Promise<CryptoKey> {
  const subtle = subtleOrThrow();

  const existing = await withStore('readonly', (store) =>
    promisify<WrappingRecord | undefined>(store.get(WRAPPING_KEY_ID))
  );
  if (existing?.key) return existing.key;

  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);

  try {
    await withStore('readwrite', (store) => promisify(store.add({ id: WRAPPING_KEY_ID, key })));
    return key;
  } catch {
    // Another tab created it first — use theirs, or nothing already stored
    // decrypts.
    const raced = await withStore('readonly', (store) =>
      promisify<WrappingRecord | undefined>(store.get(WRAPPING_KEY_ID))
    );
    if (raced?.key) return raced.key;
    throw new KeystoreError('Could not create or read the keystore wrapping key.');
  }
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
  const subtle = subtleOrThrow();

  const wrappingKey = await getWrappingKey();
  const iv = randomBytes(WRAP_IV_LENGTH);
  const wrapped = await subtle.encrypt(
    { name: 'AES-GCM', iv: asBufferSource(iv) },
    wrappingKey,
    asBufferSource(key)
  );

  await withStore('readwrite', (store) =>
    promisify(store.put({ id: recordId(namespace, name), iv, wrapped } satisfies WrappedRecord))
  );
}

/** Read a key back, or null if it was never stored. */
export async function getKey(
  name: string,
  options?: KeystoreOptions
): Promise<Uint8Array | null> {
  assertName(name);
  const namespace = namespaceOf(options);
  const subtle = subtleOrThrow();

  const record = await withStore('readonly', (store) =>
    promisify<WrappedRecord | undefined>(store.get(recordId(namespace, name)))
  );
  if (!record) return null;

  const wrappingKey = await getWrappingKey();
  try {
    const plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: asBufferSource(record.iv) },
      wrappingKey,
      record.wrapped
    );
    return new Uint8Array(plain);
  } catch {
    throw new KeystoreError(
      `Stored key "${name}" could not be unwrapped. The keystore was likely cleared or partially deleted — delete the key and create a new one.`
    );
  }
}

export async function hasKey(name: string, options?: KeystoreOptions): Promise<boolean> {
  assertName(name);
  const namespace = namespaceOf(options);
  const record = await withStore('readonly', (store) =>
    promisify<WrappedRecord | undefined>(store.get(recordId(namespace, name)))
  );
  return record !== undefined;
}

/** Delete a key. Deleting one that does not exist is not an error. */
export async function deleteKey(name: string, options?: KeystoreOptions): Promise<void> {
  assertName(name);
  const namespace = namespaceOf(options);
  await withStore('readwrite', (store) =>
    promisify(store.delete(recordId(namespace, name)))
  );
}

/**
 * Read a key, generating and storing a fresh one on first call.
 *
 * This is the usual entry point: it gives a device a stable 32-byte key that
 * survives restarts and never touches disk unwrapped.
 */
export async function getOrCreateKey(
  name: string,
  options?: KeystoreOptions
): Promise<Uint8Array> {
  const existing = await getKey(name, options);
  if (existing) return existing;

  const key = randomBytes(32);
  await setKey(name, key, options);
  // Re-read rather than returning the local copy, so a tab that lost a creation
  // race returns the key that actually got stored.
  return (await getKey(name, options)) ?? key;
}

export { KeystoreError } from './types.js';
export type { KeystoreOptions, KeystoreApi } from './types.js';
