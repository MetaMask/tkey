import { bytesToHex } from "@noble/curves/utils.js";
import { bigIntReplacer, generatePrivateExcludingIndexes, getPubKeyPoint } from "@tkey/common-types";
import { generatePrivate } from "@toruslabs/eccrypto";
import { deepStrictEqual, throws } from "assert";
import stringify from "json-stable-stringify";

import { AuthMetadata, generateRandomPolynomial, Metadata } from "../src/index";

const PRIVATE_KEY = bytesToHex(generatePrivate());

function createTestMetadata(privKeyBN) {
  const shareIndexes = [1n, 2n];
  shareIndexes.push(generatePrivateExcludingIndexes(shareIndexes));
  const poly = generateRandomPolynomial(1, privKeyBN);
  const shares = poly.generateShares(shareIndexes);
  const metadata = new Metadata(getPubKeyPoint(privKeyBN));
  metadata.addFromPolynomialAndShares(poly, shares);
  metadata.setGeneralStoreDomain("something", { test: "oh this is an object" });
  return metadata;
}

describe("AuthMetadata", function () {
  it("#should authenticate and serialize and deserialize into JSON seamlessly", async function () {
    const privKeyBN = BigInt(`0x${PRIVATE_KEY}`);
    const metadata = createTestMetadata(privKeyBN);
    const a = new AuthMetadata(metadata, privKeyBN);
    const stringified = stringify(a);
    const metadataSerialized = Metadata.fromJSON(JSON.parse(stringify(metadata)));
    const final = AuthMetadata.fromJSON(JSON.parse(stringified));
    deepStrictEqual(final.metadata, metadataSerialized, "Must be equal");
  });

  it("#should round-trip: stringify -> parse -> fromJSON preserves metadata fields", function () {
    const privKeyBN = BigInt(`0x${PRIVATE_KEY}`);
    const metadata = createTestMetadata(privKeyBN);
    const auth = new AuthMetadata(metadata, privKeyBN);
    const parsed = JSON.parse(stringify(auth, { replacer: bigIntReplacer }));
    const restored = AuthMetadata.fromJSON(parsed);
    deepStrictEqual(restored.metadata.pubKey.x, metadata.pubKey.x, "pubKey.x must match");
    deepStrictEqual(restored.metadata.pubKey.y, metadata.pubKey.y, "pubKey.y must match");
    deepStrictEqual(restored.metadata.nonce, metadata.nonce, "nonce must match");
    deepStrictEqual(restored.metadata.generalStore, metadata.generalStore, "generalStore must match");
  });

  it("#should round-trip multiple times without corruption", function () {
    const privKeyBN = BigInt(`0x${PRIVATE_KEY}`);
    const metadata = createTestMetadata(privKeyBN);

    const auth1 = new AuthMetadata(metadata, privKeyBN);
    const parsed1 = JSON.parse(stringify(auth1, { replacer: bigIntReplacer }));
    const restored1 = AuthMetadata.fromJSON(parsed1);

    const auth2 = new AuthMetadata(restored1.metadata, privKeyBN);
    const parsed2 = JSON.parse(stringify(auth2, { replacer: bigIntReplacer }));
    const restored2 = AuthMetadata.fromJSON(parsed2);

    deepStrictEqual(
      stringify(restored1.metadata, { replacer: bigIntReplacer }),
      stringify(restored2.metadata, { replacer: bigIntReplacer }),
      "double round-trip must be stable"
    );
  });

  it("#should reject tampered signature", function () {
    const privKeyBN = BigInt(`0x${PRIVATE_KEY}`);
    const metadata = createTestMetadata(privKeyBN);
    const auth = new AuthMetadata(metadata, privKeyBN);
    const parsed = JSON.parse(stringify(auth, { replacer: bigIntReplacer }));
    parsed.sig = parsed.sig.slice(0, -2) + "00";
    throws(() => AuthMetadata.fromJSON(parsed), /not valid|invalid/i, "tampered sig must be rejected");
  });

  it("#should reject signature from wrong key", function () {
    const privKeyBN = BigInt(`0x${PRIVATE_KEY}`);
    const otherKey = BigInt(`0x${bytesToHex(generatePrivate())}`);
    const metadata = createTestMetadata(privKeyBN);
    const auth = new AuthMetadata(metadata, otherKey);
    const parsed = JSON.parse(stringify(auth, { replacer: bigIntReplacer }));
    throws(() => AuthMetadata.fromJSON(parsed), /not valid|invalid/i, "wrong key sig must be rejected");
  });

  it("#should throw when toJSON called without privKey", function () {
    const privKeyBN = BigInt(`0x${PRIVATE_KEY}`);
    const metadata = createTestMetadata(privKeyBN);
    const auth = new AuthMetadata(metadata);
    throws(() => auth.toJSON(), /privkey unavailable/i, "toJSON without privKey must throw");
  });

  it("#should throw when fromJSON called with missing data", function () {
    throws(() => AuthMetadata.fromJSON({}), /metadata/i, "missing data must throw");
    throws(() => AuthMetadata.fromJSON({ data: null }), /metadata/i, "null data must throw");
  });

  it("#should preserve polyIDList through round-trip", function () {
    const privKeyBN = BigInt(`0x${PRIVATE_KEY}`);
    const metadata = createTestMetadata(privKeyBN);
    const auth = new AuthMetadata(metadata, privKeyBN);
    const parsed = JSON.parse(stringify(auth, { replacer: bigIntReplacer }));
    const restored = AuthMetadata.fromJSON(parsed);
    deepStrictEqual(restored.metadata.polyIDList.length, metadata.polyIDList.length, "polyIDList length must match");
    for (let i = 0; i < metadata.polyIDList.length; i++) {
      deepStrictEqual(restored.metadata.polyIDList[i][0], metadata.polyIDList[i][0], `polyID[${i}] must match`);
      deepStrictEqual(
        restored.metadata.polyIDList[i][1].sort(),
        metadata.polyIDList[i][1].sort(),
        `shareIndexes[${i}] must match`
      );
    }
  });

  it("#should be JSON.parse compatible with bigIntReplacer output", function () {
    const privKeyBN = BigInt(`0x${PRIVATE_KEY}`);
    const metadata = createTestMetadata(privKeyBN);
    const auth = new AuthMetadata(metadata, privKeyBN);
    const jsonStr = stringify(auth, { replacer: bigIntReplacer });
    const parsed = JSON.parse(jsonStr);
    const restored = AuthMetadata.fromJSON(parsed);
    deepStrictEqual(restored.metadata.pubKey.x, metadata.pubKey.x, "pubKey.x must survive bigIntReplacer");
  });
});
