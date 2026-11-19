# @tkey/common-types

## 18.0.0

### Major Changes

- bf3e6b0: Move all packages to the 2026 Q4 toolchain.

  - Require Node >=24.22.0 and npm >=12. Development and CI use Node 26 as well as the Node 24.22 floor.
  - `types` now points at `dist/lib.cjs/index.d.ts`. The `dist/lib.cjs/types/` folder is removed.
  - Each package now ships one bundled file for each format (`dist/lib.cjs/index.js` and `dist/lib.esm/index.js`). Deep imports of other files under `dist/` no longer resolve.
  - Remove the `@babel/runtime` peer dependency.
  - Public types now follow `strictNullChecks`. Fields that can be unset are optional: `TKey.storeDeviceShare`, `AuthMetadata.privKey`, `ShareRequestArgs.encShareInTransit`, `ShareRequest.encShareInTransit` and `customInfo`, and `ShareTransferModule.currentEncKey` and `requestStatusCheckId`. `TKey.metadata` and `TKey.lastFetchedCloudMetadata` are typed `Metadata | undefined`.
  - `ITKey.secp256k1Key` is now typed `bigint | null` and `ITKey.ed25519Key` is now typed `Uint8Array | null`. The value is `null` until the key is reconstructed or imported.
  - `LocalTransitionShares` is now `Array<bigint | undefined>`. An `undefined` entry is the service-provider slot. `IStorageLayer.setMetadataStream` accepts the same `privKey` type.
  - `privKey` is now required in `TKey.addLocalMetadataTransitions` and `TKey.setAuthMetadataBulk`.
  - `TKey.getTKeyStoreItem` now rejects when the item does not exist. Before, it resolved `undefined`.
  - Remove `TKey._deleteTKeyStoreItem` from `TKey`, `ITKeyApi`, and the module API. No replacement is available.
  - The return type of `fromJSON` on service providers and storage layers now includes `undefined`, which they already returned when the input did not match.
  - Update runtime dependencies to `@toruslabs/customauth` 23, `@toruslabs/torus.js` 19, `@toruslabs/eccrypto` 8, `@toruslabs/metadata-helpers` 9, `@toruslabs/http-helpers` 10, `@toruslabs/fetch-node-details` 17, and `@toruslabs/constants` 17.
  - `@tkey/service-provider-sfa`: remove `useDkg` from `Web3AuthOptions`. torus.js 19 removed the option. When a user has no key yet, the client now always makes the shares and imports them. `@tkey/common-types` is now a dependency, because the published types import from it.
  - `@tkey/service-provider-torus`: `customAuthArgs` follows CustomAuth 23. `metadataUrl` is removed. The optional `sentry` peer is now `@sentry/core` 11.
