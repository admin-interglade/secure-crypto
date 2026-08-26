/**
 * Regenerate test/vectors.json.
 *
 * Run this ONLY when intentionally introducing a new format version. If a
 * change to the library alters an existing vector, that is a wire-format break:
 * data encrypted by an older release would stop decrypting. Bump the version
 * byte and add new vectors instead of rewriting old ones.
 *
 *   npm run vectors
 */

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { AlgorithmName } from '../src/core/aead.js';
import { hexToBytes } from '../src/core/encoding.js';
import { FORMAT_VERSION } from '../src/core/envelope.js';
import { encryptDeterministic, encryptWithPasswordDeterministic } from '../test/deterministic.js';

const KEY_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const NONCE24_HEX = '404142434445464748494a4b4c4d4e4f5051525354555657';
const NONCE12_HEX = '404142434445464748494a4b';
const SALT_HEX = '9f8e7d6c5b4a39281706f5e4d3c2b1a0';

const PLAINTEXTS: Array<{ name: string; value: string }> = [
  { name: 'empty', value: '' },
  { name: 'ascii', value: 'attack at dawn' },
  { name: 'unicode', value: 'passphrase: 秘密 🔐 café' },
  { name: 'json', value: '{"cardNumber":"4111111111111111","cvv":"123"}' },
  { name: 'long', value: 'A'.repeat(4096) },
];

const key = hexToBytes(KEY_HEX);
const salt = hexToBytes(SALT_HEX);

function nonceFor(algorithm: AlgorithmName): Uint8Array {
  return hexToBytes(algorithm === 'aes-256-gcm' ? NONCE12_HEX : NONCE24_HEX);
}

const keyVectors = [];
for (const algorithm of ['xchacha20-poly1305', 'aes-256-gcm'] as const) {
  for (const plaintext of PLAINTEXTS) {
    keyVectors.push({
      name: `${algorithm}/${plaintext.name}`,
      algorithm,
      keyHex: KEY_HEX,
      nonceHex: algorithm === 'aes-256-gcm' ? NONCE12_HEX : NONCE24_HEX,
      plaintext: plaintext.value,
      envelope: encryptDeterministic({
        plaintext: plaintext.value,
        key,
        nonce: nonceFor(algorithm),
        algorithm,
      }),
    });
  }
  keyVectors.push({
    name: `${algorithm}/with-aad`,
    algorithm,
    keyHex: KEY_HEX,
    nonceHex: algorithm === 'aes-256-gcm' ? NONCE12_HEX : NONCE24_HEX,
    aad: 'user-42:record-7',
    plaintext: 'bound to context',
    envelope: encryptDeterministic({
      plaintext: 'bound to context',
      key,
      nonce: nonceFor(algorithm),
      algorithm,
      aad: 'user-42:record-7',
    }),
  });
}

const passwordSpecs = [
  { name: 'pbkdf2/default-alg', algorithm: 'xchacha20-poly1305' as const, kdfOptions: { iterations: 10_000 } },
  { name: 'pbkdf2/aes', algorithm: 'aes-256-gcm' as const, kdfOptions: { iterations: 10_000 } },
  { name: 'scrypt/default-alg', algorithm: 'xchacha20-poly1305' as const, kdfOptions: { kdf: 'scrypt' as const, logN: 12, r: 8, p: 1 } },
];

const passwordVectors = [];
for (const spec of passwordSpecs) {
  passwordVectors.push({
    name: spec.name,
    algorithm: spec.algorithm,
    password: 'correct horse battery staple',
    saltHex: SALT_HEX,
    nonceHex: spec.algorithm === 'aes-256-gcm' ? NONCE12_HEX : NONCE24_HEX,
    kdfOptions: spec.kdfOptions,
    plaintext: 'my diary entry 秘密',
    envelope: await encryptWithPasswordDeterministic({
      plaintext: 'my diary entry 秘密',
      password: 'correct horse battery staple',
      salt,
      nonce: nonceFor(spec.algorithm),
      algorithm: spec.algorithm,
      kdfOptions: spec.kdfOptions,
    }),
  });
}

const output = {
  $comment:
    'Known-answer vectors for the secure-crypto envelope format. Run the same file on web, Node and React Native: identical results prove cross-platform compatibility. Never edit an existing vector.',
  formatVersion: FORMAT_VERSION,
  keyVectors,
  passwordVectors,
};

const outPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'test', 'vectors.json');
writeFileSync(outPath, JSON.stringify(output, null, 2) + '\n');
console.log(
  `Wrote ${keyVectors.length} key vectors and ${passwordVectors.length} password vectors to ${outPath}`
);
