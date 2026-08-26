# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through
[GitHub Security Advisories](https://github.com/admin-interglade/secure-crypto/security/advisories/new),
or email **tech@interglade.com**.

Please include: affected version, a description of the issue, and a proof of
concept or reproduction steps if you have one.

We aim to acknowledge a report within 3 working days and to ship a fix or a
mitigation plan within 30 days. We will credit you in the advisory unless you
prefer otherwise.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

Until 1.0.0, only the latest minor version receives security fixes.

## Scope

**In scope**

- Flaws in the envelope format, or in how algorithm/KDF parameters are bound.
- Nonce or salt reuse, or weakness in how randomness is obtained.
- Any input that causes plaintext, keys, or key material to leak.
- Ciphertext that is accepted as authentic after being modified.
- Differences in behaviour between platforms that break cross-platform
  compatibility in a security-relevant way.
- Errors that leak enough detail to build a decryption oracle.

**Out of scope**

- Attacks that require a compromised device, a malicious browser extension, or
  code execution inside the host application. Client-side encryption cannot
  defend against an attacker already running in your process.
- Weak user-chosen passwords. Key stretching raises the cost of guessing; it
  cannot fix `password123`.
- Plaintext length disclosure. Envelope size reveals approximate payload size by
  design — pad before encrypting if that matters to you.
- Vulnerabilities in `@noble/ciphers` or `@noble/hashes` themselves; report
  those upstream, then tell us so we can pin a fixed version.

## Cryptography

Primitives come from [@noble](https://github.com/paulmillr/noble-ciphers),
which is independently audited. This library composes them; it does not
implement any primitive itself.

| Purpose | Algorithm |
| --- | --- |
| AEAD (default) | XChaCha20-Poly1305, 24-byte random nonce |
| AEAD (option) | AES-256-GCM, 12-byte random nonce |
| Password KDF (default) | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt |
| Password KDF (option) | scrypt, N=2^15, r=8, p=1 |
| Randomness | `crypto.getRandomValues` only — no fallback |

## Wire format stability

The envelope carries a version byte. `decrypt` will read every format version
this library has ever written. A change that breaks an existing known-answer
vector in `test/vectors.json` is a breaking change requiring a new version
byte — never a test to update.
