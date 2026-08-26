import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/keystore/index.ts', 'src/keystore/index.native.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  treeshake: true,
  sourcemap: true,
  target: 'es2020',
  // @noble/* is ESM-only. Bundling it in makes the published package
  // self-contained, so Metro and Jest never have to resolve an ESM dependency.
  noExternal: [/@noble\//],
  outExtension: ({ format }) => ({ js: format === 'cjs' ? '.cjs' : '.js' }),
});
