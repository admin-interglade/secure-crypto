# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-26

Initial release. Requires Node 20 or newer.

Verified end to end: the known-answer vectors in `test/vectors.json` produce
byte-identical results under Node, and on a physical Android device via
`examples/react-native-verify/`.

### Added
- `@interglade/secure-crypto/keystore` — platform-backed key storage: the iOS
  Keychain / Android Keystore via `react-native-keychain`, and a non-extractable
  WebCrypto wrapping key in IndexedDB on the web.
- On-device React Native verification screen under `examples/react-native-verify/`.
- `encrypt` / `decrypt` with a 32-byte key.
- `encryptWithPassword` / `decryptWithPassword` with a per-call random salt.
- `deriveKey`, `generateKey`, `generateSalt`.
- XChaCha20-Poly1305 (default) and AES-256-GCM.
- PBKDF2-SHA256 (600,000 iterations by default) and scrypt key derivation.
- Associated data (AAD) support on every encrypt/decrypt entry point.
- Versioned, self-describing `sc1.` envelope format; the header is authenticated
  as associated data, so algorithm and KDF parameters cannot be downgraded.
- `inspect` and `isEnvelope` for reading envelope metadata without a key.
- `isCryptoAvailable` / `assertCryptoAvailable` for fail-fast startup checks.
- Typed error hierarchy under `SecureCryptoError`.
- Pure-JS UTF-8 and base64url helpers that do not rely on `TextEncoder`,
  `Buffer` or `btoa`, so the library behaves identically on Hermes.
- ESM and CommonJS builds with per-condition type declarations.

### Security
- Callers cannot supply a nonce; one is always drawn from the platform CSPRNG.
- No `Math.random()` fallback — a missing CSPRNG throws `CryptoUnavailableError`
  with setup instructions.
- `DecryptionFailedError` does not distinguish a wrong key from tampered data.

[Unreleased]: https://github.com/admin-interglade/secure-crypto/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/admin-interglade/secure-crypto/releases/tag/v0.1.0
