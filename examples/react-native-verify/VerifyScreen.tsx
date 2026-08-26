/**
 * On-device verification screen for @interglade/secure-crypto.
 *
 * Drop this into a bare React Native app and render it. It runs the same
 * known-answer vectors the Node test suite runs, plus live round-trip and
 * tamper-detection checks, and reports pass/fail on the actual device.
 *
 * This is the check that Node cannot do for you: the test suite only
 * *simulates* Hermes by deleting globals. Green here means an envelope written
 * on this phone really does open on your server.
 *
 * Setup instructions: see README.md in this folder.
 */

import React, { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
import {
  DecryptionFailedError,
  decrypt,
  decryptWithPassword,
  encrypt,
  encryptWithPassword,
  generateKey,
  hexToBytes,
  inspect,
  isCryptoAvailable,
  base64UrlDecode,
  base64UrlEncode,
} from '@interglade/secure-crypto';

import vectors from './vectors.json';

type Status = 'pass' | 'fail';

interface Result {
  name: string;
  status: Status;
  detail: string;
  ms: number;
}

/** Run one check, timing it and turning any throw into a failure row. */
async function check(name: string, fn: () => Promise<string>): Promise<Result> {
  const started = Date.now();
  try {
    const detail = await fn();
    return { name, status: 'pass', detail, ms: Date.now() - started };
  } catch (error) {
    const message = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    return { name, status: 'fail', detail: message, ms: Date.now() - started };
  }
}

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

async function runAllChecks(onResult: (result: Result) => void): Promise<void> {
  const push = async (name: string, fn: () => Promise<string>) => {
    onResult(await check(name, fn));
  };

  // ---- 1. Environment -----------------------------------------------------
  await push('CSPRNG available', async () => {
    assert(
      isCryptoAvailable(),
      "No secure RNG. Add `import 'react-native-get-random-values';` as the FIRST line of index.js."
    );
    return 'globalThis.crypto.getRandomValues present';
  });

  await push('Vector file matches format version', async () => {
    assert(vectors.formatVersion === 1, `Expected format version 1, got ${vectors.formatVersion}`);
    return `format v${vectors.formatVersion}`;
  });

  // ---- 2. Known-answer vectors (the cross-platform contract) ---------------
  for (const vector of vectors.keyVectors) {
    await push(`KAT ${vector.name}`, async () => {
      const key = hexToBytes(vector.keyHex);
      const plaintext = await decrypt(vector.envelope, key, { aad: (vector as any).aad });
      assert(
        plaintext === vector.plaintext,
        `Decrypted to ${JSON.stringify(plaintext.slice(0, 40))}`
      );
      assert(
        inspect(vector.envelope).algorithm === vector.algorithm,
        'Envelope reports the wrong algorithm'
      );
      return `${vector.plaintext.length} chars, ${vector.algorithm}`;
    });
  }

  for (const vector of vectors.passwordVectors) {
    await push(`KAT ${vector.name}`, async () => {
      const plaintext = await decryptWithPassword(vector.envelope, vector.password);
      assert(plaintext === vector.plaintext, 'Password vector decrypted to the wrong value');
      return inspect(vector.envelope).kdf;
    });
  }

  // ---- 3. Live round trips on this device ---------------------------------
  const messages = ['', 'attack at dawn', 'unicode 秘密 🔐 café', 'x'.repeat(100_000)];
  for (const algorithm of ['xchacha20-poly1305', 'aes-256-gcm'] as const) {
    await push(`Round trip (${algorithm})`, async () => {
      const key = generateKey();
      for (const message of messages) {
        const envelope = await encrypt(message, key, { algorithm });
        assert(
          (await decrypt(envelope, key)) === message,
          `Failed for a ${message.length}-char payload`
        );
      }
      return `${messages.length} payloads up to 100 KB`;
    });
  }

  await push('Round trip (password)', async () => {
    const envelope = await encryptWithPassword('diary 秘密', 'hunter2', { iterations: 10_000 });
    assert((await decryptWithPassword(envelope, 'hunter2')) === 'diary 秘密', 'Mismatch');
    return '10k PBKDF2 iterations';
  });

  // ---- 4. Security properties must hold here too --------------------------
  await push('Rejects the wrong key', async () => {
    const envelope = await encrypt('secret', generateKey());
    try {
      await decrypt(envelope, generateKey());
    } catch (error) {
      assert(error instanceof DecryptionFailedError, 'Threw the wrong error type');
      return 'DecryptionFailedError as expected';
    }
    throw new Error('Decryption succeeded with the wrong key');
  });

  await push('Detects tampered ciphertext', async () => {
    const key = generateKey();
    const envelope = await encrypt('tamper me', key);
    const raw = base64UrlDecode(envelope.slice(4));
    raw[raw.length - 1] ^= 0x01;
    try {
      await decrypt('sc1.' + base64UrlEncode(raw), key);
    } catch {
      return 'One flipped bit was caught';
    }
    throw new Error('Tampered ciphertext decrypted successfully');
  });

  await push('AAD binds an envelope to its context', async () => {
    const key = generateKey();
    const envelope = await encrypt('record', key, { aad: 'user-42' });
    assert((await decrypt(envelope, key, { aad: 'user-42' })) === 'record', 'Correct AAD failed');
    try {
      await decrypt(envelope, key, { aad: 'user-43' });
    } catch {
      return 'Wrong AAD rejected';
    }
    throw new Error('Envelope decrypted under the wrong AAD');
  });

  await push('Nonces are not reused', async () => {
    const key = generateKey();
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) seen.add(await encrypt('same input', key));
    assert(seen.size === 200, `Only ${seen.size}/200 envelopes were unique`);
    return '200 distinct envelopes from identical input';
  });

  // ---- 5. Throughput on real hardware -------------------------------------
  await push('Throughput (1 MB)', async () => {
    const key = generateKey();
    const payload = 'a'.repeat(1024 * 1024);
    const started = Date.now();
    const envelope = await encrypt(payload, key);
    await decrypt(envelope, key);
    const seconds = (Date.now() - started) / 1000;
    return `${(2 / seconds).toFixed(1)} MB/s round trip`;
  });
}

export default function VerifyScreen(): React.JSX.Element {
  const [results, setResults] = useState<Result[]>([]);
  const [running, setRunning] = useState(false);

  const run = useCallback(async () => {
    setResults([]);
    setRunning(true);
    // Yield between checks so the UI paints as results arrive.
    await runAllChecks((result) => setResults((prev) => [...prev, result]));
    setRunning(false);
  }, []);

  useEffect(() => {
    void run();
  }, [run]);

  const failed = results.filter((r) => r.status === 'fail').length;
  const allDone = !running && results.length > 0;
  const bannerStyle = running
    ? styles.bannerRunning
    : failed > 0
      ? styles.bannerFail
      : styles.bannerPass;

  return (
    <View style={styles.container}>
      <View style={[styles.banner, bannerStyle]}>
        <Text style={styles.bannerTitle}>
          {running
            ? 'Running…'
            : failed > 0
              ? `${failed} CHECK${failed === 1 ? '' : 'S'} FAILED`
              : 'ALL CHECKS PASSED'}
        </Text>
        <Text style={styles.bannerSub}>
          {results.length - failed}/{results.length} passed · {Platform.OS} {Platform.Version}
          {allDone && failed === 0 ? ' · safe to publish' : ''}
        </Text>
      </View>

      <ScrollView contentContainerStyle={styles.list}>
        {results.map((result, index) => (
          <View key={`${result.name}-${index}`} style={styles.row}>
            <Text style={result.status === 'pass' ? styles.iconPass : styles.iconFail}>
              {result.status === 'pass' ? '✓' : '✕'}
            </Text>
            <View style={styles.rowBody}>
              <Text style={styles.rowName}>{result.name}</Text>
              <Text style={result.status === 'pass' ? styles.rowDetail : styles.rowDetailFail}>
                {result.detail}
              </Text>
            </View>
            <Text style={styles.rowMs}>{result.ms}ms</Text>
          </View>
        ))}
        {running ? <ActivityIndicator style={styles.spinner} /> : null}
      </ScrollView>

      <TouchableOpacity style={styles.button} onPress={run} disabled={running}>
        <Text style={styles.buttonText}>{running ? 'Running…' : 'Run again'}</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0d1117' },
  banner: { paddingTop: 56, paddingBottom: 18, paddingHorizontal: 20 },
  bannerRunning: { backgroundColor: '#1f2937' },
  bannerPass: { backgroundColor: '#166534' },
  bannerFail: { backgroundColor: '#991b1b' },
  bannerTitle: { color: '#fff', fontSize: 22, fontWeight: '700', letterSpacing: 0.5 },
  bannerSub: { color: '#e5e7eb', fontSize: 13, marginTop: 4 },
  list: { padding: 12, paddingBottom: 32 },
  row: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    paddingVertical: 9,
    paddingHorizontal: 8,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#21262d',
  },
  iconPass: { color: '#3fb950', fontSize: 15, width: 22, fontWeight: '700' },
  iconFail: { color: '#f85149', fontSize: 15, width: 22, fontWeight: '700' },
  rowBody: { flex: 1 },
  rowName: { color: '#e6edf3', fontSize: 14, fontWeight: '600' },
  rowDetail: { color: '#8b949e', fontSize: 12, marginTop: 2 },
  rowDetailFail: { color: '#f85149', fontSize: 12, marginTop: 2 },
  rowMs: { color: '#6e7681', fontSize: 11, marginLeft: 8, marginTop: 2 },
  spinner: { marginTop: 20 },
  button: {
    margin: 16,
    padding: 15,
    borderRadius: 10,
    backgroundColor: '#238636',
    alignItems: 'center',
  },
  buttonText: { color: '#fff', fontWeight: '700', fontSize: 15 },
});
