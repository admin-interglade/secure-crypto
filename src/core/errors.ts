/**
 * Error types. Every failure mode is a distinct class so callers can branch on
 * `instanceof` instead of matching message strings.
 */

export class SecureCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecureCryptoError';
    // Required for `instanceof` to work when compiled down for Hermes / older JS engines.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** No cryptographically secure RNG was found in this JS environment. */
export class CryptoUnavailableError extends SecureCryptoError {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoUnavailableError';
  }
}

/** The envelope string is malformed, truncated, or not produced by this library. */
export class InvalidEnvelopeError extends SecureCryptoError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidEnvelopeError';
  }
}

/** The envelope was written by a newer version of the format than this build understands. */
export class UnsupportedVersionError extends SecureCryptoError {
  constructor(message: string) {
    super(message);
    this.name = 'UnsupportedVersionError';
  }
}

/**
 * Authentication failed. Deliberately does NOT distinguish between a wrong key,
 * a wrong password, a wrong AAD, and tampered ciphertext — telling them apart
 * would hand an attacker an oracle.
 */
export class DecryptionFailedError extends SecureCryptoError {
  constructor(message = 'Decryption failed: wrong key/password, wrong AAD, or the data was modified.') {
    super(message);
    this.name = 'DecryptionFailedError';
  }
}

/** A caller passed an argument this library cannot use. */
export class InvalidArgumentError extends SecureCryptoError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidArgumentError';
  }
}
