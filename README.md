# @interglade/secure-crypto

[![CI](https://github.com/admin-interglade/secure-crypto/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/admin-interglade/secure-crypto/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@interglade/secure-crypto)](https://www.npmjs.com/package/@interglade/secure-crypto)
[![license](https://img.shields.io/npm/l/@interglade/secure-crypto)](./LICENSE)

One encryption API for **React Native**, **the browser**, and **Node**. Same code, same bytes — data encrypted on a phone decrypts on your server, and vice versa.

- 🔐 Authenticated encryption only — XChaCha20-Poly1305 (default) and AES-256-GCM
- 📦 Self-contained — no native modules, no `pod install` for the crypto itself
- 🧾 Versioned, self-describing envelope — `decrypt()` needs nothing but the key
- 🧪 Cross-platform known-answer vectors, so "it works on web" means it works on Android
- 🟦 TypeScript types included
- 🪶 Built on [@noble](https://github.com/paulmillr/noble-ciphers) — audited, zero-dependency primitives

```bash
npm install @interglade/secure-crypto
```

```ts
import { encryptWithPassword, decryptWithPassword } from '@interglade/secure-crypto';

const envelope = await encryptWithPassword('4111 1111 1111 1111', userPassword);
// → "sc1.U0MBAQEAAJiQEJ..."  safe to store in a DB, a cookie, or a URL

const card = await decryptWithPassword(envelope, userPassword);
// → "4111 1111 1111 1111"
```

---

## React Native setup

React Native has no built-in secure random source, so add one polyfill (this is the only extra step, and it is a one-time thing):

```bash
npm install @interglade/secure-crypto react-native-get-random-values
cd ios && pod install && cd ..
```

Then make it the **very first import** in your entry file — above every other import, including `App`:

```js
// index.js
import 'react-native-get-random-values';   // ← must be line 1
import { AppRegistry } from 'react-native';
import App from './App';
```

After that the API is identical to web. If you skip this step you get a loud error with these instructions in it, never a silent downgrade to insecure randomness.

<details>
<summary>Troubleshooting</summary>

| Symptom | Fix |
|---|---|
| `CryptoUnavailableError` at runtime | The polyfill import is missing or not first in `index.js` |
| Changes not appearing after upgrade | `npx react-native start --reset-cache` |
| `Unable to resolve module` in Metro | `rm -rf node_modules && npm install`, then reset the cache |
| Jest cannot parse the package | Should not happen — the React Native entry is CommonJS. If it does, add `transformIgnorePatterns: ['node_modules/(?!(@interglade)/)']` |

</details>

## Web and Node

Nothing to configure. Works in Vite, Next.js, Create React App, Webpack, Web Workers, Deno, Bun, and Node 20+.

```ts
import { generateKey, encrypt, decrypt } from '@interglade/secure-crypto';

const key = generateKey();                        // 32 random bytes
const envelope = await encrypt('hello', key);
await decrypt(envelope, key);                     // → "hello"
```

---

## API

### Password-based

Simplest option. A random salt is generated per call and the KDF settings travel inside the envelope, so decryption needs only the password.

```ts
await encryptWithPassword(data, password, options?): Promise<string>
await decryptWithPassword(envelope, password, options?): Promise<string>
await decryptWithPasswordToBytes(envelope, password, options?): Promise<Uint8Array>
```

> Key derivation is **deliberately slow** (~300–800 ms, by design — it is what makes a stolen envelope expensive to brute-force). For many records, derive once with `deriveKey()` and use `encrypt()` instead.

### Key-based

Fast. Use when you already hold a 32-byte key.

```ts
generateKey(): Uint8Array
generateSalt(length?): Uint8Array

await encrypt(data, key, options?): Promise<string>
await decrypt(envelope, key, options?): Promise<string>
await decryptToBytes(envelope, key, options?): Promise<Uint8Array>

await deriveKey(password, salt, options?): Promise<Uint8Array>
```

### Options

```ts
{
  algorithm?: 'xchacha20-poly1305' | 'aes-256-gcm',  // default: xchacha20-poly1305
  aad?: string | Uint8Array,                          // associated data (see below)

  // encryptWithPassword / deriveKey only:
  kdf?: 'pbkdf2' | 'scrypt',        // default: pbkdf2
  iterations?: number,              // pbkdf2, default 600,000
  logN?: number, r?: number, p?: number,  // scrypt, default 15 / 8 / 1
}
```

### Utilities

```ts
isEnvelope(value): boolean         // cheap type guard
inspect(envelope): EnvelopeInfo    // read algorithm/KDF metadata without the key
isCryptoAvailable(): boolean
assertCryptoAvailable(): void      // call at app startup to fail fast
randomBytes(n): Uint8Array
utf8ToBytes / bytesToUtf8 / base64UrlEncode / base64UrlDecode / bytesToHex / hexToBytes / wipe
```

---

## Associated data (AAD)

AAD is not encrypted, but it *is* authenticated: decryption fails unless the exact same value is supplied. Use it to pin an envelope to its context so a valid ciphertext cannot be moved somewhere it does not belong.

```ts
const envelope = await encrypt(ssn, key, { aad: `user:${userId}` });

await decrypt(envelope, key, { aad: `user:${userId}` });   // ✅
await decrypt(envelope, key, { aad: `user:${attackerId}` }); // ❌ DecryptionFailedError
```

Without AAD, an attacker who can write to your database could copy their own encrypted row into your account and it would decrypt cleanly. With AAD, it will not.

## Errors

Every failure is a typed subclass of `SecureCryptoError`:

| Error | Meaning |
|---|---|
| `DecryptionFailedError` | Wrong key/password, wrong AAD, **or** tampered data — deliberately indistinguishable |
| `InvalidEnvelopeError` | Not an envelope, or truncated |
| `UnsupportedVersionError` | Written by a newer format version — upgrade the package |
| `CryptoUnavailableError` | No secure RNG (see React Native setup) |
| `InvalidArgumentError` | Bad key length, empty password, unknown algorithm |

```ts
import { DecryptionFailedError } from '@interglade/secure-crypto';

try {
  await decryptWithPassword(envelope, entered);
} catch (err) {
  if (err instanceof DecryptionFailedError) showMessage('Incorrect password.');
  else throw err;
}
```

---

## Envelope format

```
"sc1." + base64url( header | salt | nonce | ciphertext‖tag )
```

| Offset | Size | Meaning |
|---:|---:|---|
| 0 | 2 | magic `SC` |
| 2 | 1 | format version |
| 3 | 1 | algorithm id (1 = XChaCha20-Poly1305, 2 = AES-256-GCM) |
| 4 | 1 | KDF id (0 = raw key, 1 = PBKDF2-SHA256, 2 = scrypt) |
| 5 | 4 | KDF parameters (iterations, or logN·r·p) |
| 9 | 1 | salt length |
| 10 | 1 | nonce length |

The **entire header is fed to the cipher as associated data**, which binds the version and cost parameters to the ciphertext — an attacker cannot rewrite the header to downgrade the algorithm or weaken the KDF without failing the authentication check.

The version byte is the compatibility guarantee: **`decrypt()` will always read every format version this library has ever written.**

---

## Key storage

```ts
import { getOrCreateKey, setKey, getKey, deleteKey } from '@interglade/secure-crypto/keystore';
```

Same API on every platform, different mechanism underneath:

| Platform | Backing store |
|---|---|
| React Native | iOS Keychain / Android Keystore via `react-native-keychain` (hardware-backed where available) |
| Web | IndexedDB, wrapped under a **non-extractable** WebCrypto key |

The usual pattern is one call — generate a device key on first launch, reuse it forever after:

```ts
const key = await getOrCreateKey('device-key');
const envelope = await encrypt(secret, key);
```

```ts
setKey(name, key, options?): Promise<void>
getKey(name, options?): Promise<Uint8Array | null>
hasKey(name, options?): Promise<boolean>
deleteKey(name, options?): Promise<void>
getOrCreateKey(name, options?): Promise<Uint8Array>
isKeystoreAvailable(): boolean
```

Options: `namespace` (isolate one app's keys from another's), plus `requireAuthentication` and `authenticationPrompt` on React Native to gate reads behind biometrics or the device passcode.

### React Native

```bash
npm install react-native-keychain
cd ios && pod install && cd ..
```

It is an **optional** peer dependency — importing the keystore never crashes an app that does not use it, and `isKeystoreAvailable()` tells you whether the native module is linked. Keys are stored `WHEN_UNLOCKED_THIS_DEVICE_ONLY`, so they are unreadable while the device is locked and never migrate to a restored backup or a new device.

### Web

Nothing to install. On first use the browser generates an AES-GCM key with `extractable: false` — key material the browser will not hand back to JavaScript, not even to this library — and every stored key is encrypted under it. What lands on disk is ciphertext, so a stolen browser profile yields nothing usable.

> **This does not stop XSS.** Script running on your origin can simply call `getKey()`. A Content Security Policy is what defends against that; the keystore defends against offline access to stored data.

**Not for servers.** In Node there is no IndexedDB and the keystore throws with a pointer to the right answer: a KMS, a secrets manager, or an environment variable.

---

## Security model

**What this protects:** data at rest (databases, `AsyncStorage`, files, backups) and data in transit through systems you do not trust. An attacker with the ciphertext and no key learns nothing but its approximate length.

**What it does not protect:**

- **A compromised device.** If malware or a hostile browser extension runs in your app's context, it can read the key and the plaintext.
- **Authorization.** Client-side encryption is not a substitute for server-side access control.
- **Passwords the user chose badly.** A 600k-iteration KDF slows guessing; it cannot rescue `password123`.
- **Metadata.** Envelope length reveals plaintext length. Pad if that matters.

**Rules that matter more than the cipher choice:**

1. **Never hardcode a key in app source.** A React Native bundle and a JS bundle are both trivially readable — anyone can extract it. Derive from a user secret, or fetch per-session from your backend.
2. **Never reuse a nonce.** This library always draws one from the CSPRNG and never lets you supply your own; that is deliberate.
3. **Store keys in the platform keystore**, not `AsyncStorage` or `localStorage` — use `react-native-keychain` on mobile and a non-extractable `CryptoKey` in IndexedDB on web.
4. **Rotate the format, not the vectors.** If you need a new algorithm, bump the version byte and keep reading old envelopes.

Found a vulnerability? Please open a security advisory on the repository rather than a public issue.

---

## Performance

Pure JS, so throughput is roughly 10–40 MB/s depending on device — ample for records, tokens, messages and JSON blobs; **not** intended for encrypting video files on a low-end phone. If you need bulk-file throughput, wire `react-native-quick-crypto` in behind this same API.

`encryptWithPassword` cost is dominated by the KDF, not the cipher: budget several hundred milliseconds per call and do it once per session.

## Contributing

```bash
npm install
npm test          # 78 tests, incl. cross-platform known-answer vectors
npm run typecheck
npm run build
```

`test/vectors.json` is frozen. If a change makes a vector fail, the wire format changed — that is a breaking change requiring a version bump, not a test to update.

## License

MIT
