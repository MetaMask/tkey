---
"@tkey/chrome-storage": patch
"@tkey/common-types": patch
"@tkey/core": patch
"@tkey/default": patch
"@tkey/private-keys": patch
"@tkey/security-questions": patch
"@tkey/seed-phrase": patch
"@tkey/service-provider-base": patch
"@tkey/service-provider-sfa": patch
"@tkey/service-provider-torus": patch
"@tkey/share-serialization": patch
"@tkey/share-transfer": patch
"@tkey/storage-layer-torus": patch
"@tkey/web-storage": patch
---

Require Node >=24.22.0 and npm >=12, and point package types at dist/lib.cjs/index.d.ts. Drop the unused @babel/runtime peer dependency.

The pack:lerna script is removed. Compatibility workflows pack with npm run pack.

Oxlint does not replace @typescript-eslint/no-explicit-any, no-empty, import/no-extraneous-dependencies, or @typescript-eslint/no-var-requires. It still reports typescript no-this-alias, vitest expect-expect, and vitest no-conditional-expect, so those suppressions stay.
