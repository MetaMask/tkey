---
"@tkey/chrome-storage": major
"@tkey/common-types": major
"@tkey/core": major
"@tkey/default": major
"@tkey/private-keys": major
"@tkey/security-questions": major
"@tkey/seed-phrase": major
"@tkey/service-provider-base": major
"@tkey/service-provider-sfa": major
"@tkey/service-provider-torus": major
"@tkey/share-serialization": major
"@tkey/share-transfer": major
"@tkey/storage-layer-torus": major
"@tkey/web-storage": major
---

Move all packages to the 2026 Q4 toolchain.

- Require Node >=24.22.0 and npm >=12. Development and CI use Node 26 as well as the Node 24.22 floor.
- `types` now points at `dist/lib.cjs/index.d.ts`. The `dist/lib.cjs/types/` folder is removed.
- Each package now ships one bundled file for each format (`dist/lib.cjs/index.js` and `dist/lib.esm/index.js`). Deep imports of other files under `dist/` no longer resolve.
- Remove the `@babel/runtime` peer dependency.
- Public types now follow `strictNullChecks`. Fields that can be unset are optional: `TKey.storeDeviceShare`, `AuthMetadata.privKey`, `ShareRequestArgs.encShareInTransit`, `ShareRequest.encShareInTransit` and `customInfo`, and `ShareTransferModule.currentEncKey` and `requestStatusCheckId`. `TKey.metadata` and `TKey.lastFetchedCloudMetadata` are typed `Metadata | undefined`.
- The return type of `fromJSON` on service providers and storage layers now includes `undefined`, which they already returned when the input did not match.
- Update runtime dependencies to `@toruslabs/eccrypto` 8, `@toruslabs/metadata-helpers` 9, `@toruslabs/http-helpers` 10, `@toruslabs/fetch-node-details` 17, and `@toruslabs/constants` 17.
