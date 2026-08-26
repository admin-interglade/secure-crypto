/**
 * Isolates the one line that reaches for the native module.
 *
 * `react-native-keychain` is an optional peer dependency and a native module,
 * so it can only be resolved at call time, and never under Node. Keeping that
 * resolution in its own module means the test suite can substitute it at the
 * module boundary instead of the library exposing a test hook in its public API.
 */

// Provided by Metro and by the CommonJS bundle that the React Native export
// condition resolves to. Declared because this package builds without ambient
// Node types.
declare const require: (id: string) => unknown;

/** Resolve `react-native-keychain`, throwing if it is not installed or linked. */
export function loadNativeKeychain(): unknown {
  return require('react-native-keychain');
}
