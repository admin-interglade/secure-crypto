# On-device verification

The Node test suite only *simulates* Hermes by deleting `TextEncoder`, `Buffer` and `btoa`. This screen runs the real thing on a real phone: the same known-answer vectors, plus live round-trips, tamper detection and a throughput measurement.

**Run this on Android and iOS before publishing.** Green here is what turns "should work on mobile" into "does work on mobile".

## Setup (~15 minutes)

### 1. Create a bare React Native app

```bash
npx @react-native-community/cli init CryptoVerify
cd CryptoVerify
```

### 2. Install the library

Point npm at your local tarball so you test exactly what would be published:

```bash
# in the secure-crypto repo
npm run build && npm pack

# in CryptoVerify
npm install ../secure-crypto/interglade-secure-crypto-0.1.0.tgz
npm install react-native-get-random-values
cd ios && pod install && cd ..
```

> Once published, this becomes `npm install @interglade/secure-crypto react-native-get-random-values`.

### 3. Add the polyfill as the first line of `index.js`

```js
// index.js
import 'react-native-get-random-values';   // ← MUST be line 1, above every other import
import { AppRegistry } from 'react-native';
import App from './App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);
```

### 4. Copy in this folder's two files

```bash
cp ../secure-crypto/examples/react-native-verify/VerifyScreen.tsx .
cp ../secure-crypto/examples/react-native-verify/vectors.json .
```

### 5. Render it

```tsx
// App.tsx
import VerifyScreen from './VerifyScreen';
export default function App() {
  return <VerifyScreen />;
}
```

### 6. Run on both platforms

```bash
npx react-native run-android
npx react-native run-ios
```

## What you should see

A green **ALL CHECKS PASSED** banner with ~24 rows:

| Group | Checks |
|---|---|
| Environment | CSPRNG present, vector format version matches |
| Known-answer vectors | 12 key vectors + 3 password vectors — byte-identical to Node |
| Live round trips | both ciphers, empty → 100 KB payloads, unicode, password mode |
| Security properties | wrong key rejected, single flipped bit caught, AAD enforced, 200 unique nonces |
| Performance | 1 MB round-trip throughput on this device |

## If something fails

| Failure | Cause |
|---|---|
| **CSPRNG available** ✕ | The polyfill import is missing or not the first line of `index.js` |
| **KAT …** ✕ | Serious — the device produces different bytes than Node. Do not publish; open an issue with the device and OS version |
| **Round trip** ✕ on large payloads only | Memory pressure on a low-end device, not a correctness bug |
| Metro cannot resolve the module | `rm -rf node_modules && npm install`, then `npx react-native start --reset-cache` |

## Keeping vectors in sync

`vectors.json` is a copy of `test/vectors.json`. If the vectors are ever regenerated, refresh it:

```bash
npm run example:sync
```
