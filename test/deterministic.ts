/**
 * Test-only helpers that build an envelope from a caller-supplied nonce/salt.
 *
 * These are NOT exported from the package. Letting application code choose a
 * nonce is the single easiest way to destroy AEAD security, so the public API
 * always draws one from the CSPRNG. Fixed inputs are needed here only to make
 * known-answer vectors reproducible.
 */

import {
  aeadEncrypt,
  algorithmId,
  type AlgorithmName,
} from '../src/core/aead.js';
import { buildAad, buildHeader, packEnvelope } from '../src/core/envelope.js';
import { KDF_NONE, deriveKeyWith, packKdfParams, resolveKdf, type KdfOptions } from '../src/core/kdf.js';
import { toBytes } from '../src/core/encoding.js';

const EMPTY = new Uint8Array(0);

export function encryptDeterministic(input: {
  plaintext: string | Uint8Array;
  key: Uint8Array;
  nonce: Uint8Array;
  algorithm: AlgorithmName;
  aad?: string | Uint8Array;
}): string {
  const userAad = input.aad === undefined ? EMPTY : toBytes(input.aad, 'aad');
  const header = buildHeader({
    algId: algorithmId(input.algorithm),
    kdfId: KDF_NONE,
    kdfParams: new Uint8Array(4),
    saltLength: 0,
    nonceLength: input.nonce.length,
  });
  const ciphertext = aeadEncrypt(
    input.algorithm,
    input.key,
    input.nonce,
    buildAad(header, userAad),
    toBytes(input.plaintext, 'plaintext')
  );
  return packEnvelope(header, EMPTY, input.nonce, ciphertext);
}

export async function encryptWithPasswordDeterministic(input: {
  plaintext: string | Uint8Array;
  password: string;
  salt: Uint8Array;
  nonce: Uint8Array;
  algorithm: AlgorithmName;
  kdfOptions: KdfOptions;
  aad?: string | Uint8Array;
}): Promise<string> {
  const kdf = resolveKdf(input.kdfOptions);
  const userAad = input.aad === undefined ? EMPTY : toBytes(input.aad, 'aad');
  const header = buildHeader({
    algId: algorithmId(input.algorithm),
    kdfId: kdf.kdfId,
    kdfParams: packKdfParams(kdf),
    saltLength: input.salt.length,
    nonceLength: input.nonce.length,
  });
  const key = await deriveKeyWith(input.password, input.salt, kdf);
  const ciphertext = aeadEncrypt(
    input.algorithm,
    key,
    input.nonce,
    buildAad(header, userAad),
    toBytes(input.plaintext, 'plaintext')
  );
  return packEnvelope(header, input.salt, input.nonce, ciphertext);
}
