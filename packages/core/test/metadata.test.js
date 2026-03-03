import { bytesToHex, bytesToNumberBE } from "@noble/curves/utils.js";
import { getPubKeyPoint } from "@tkey/common-types";
import { generatePrivate } from "@toruslabs/eccrypto";
import { deepStrictEqual } from "assert";
import stringify from "json-stable-stringify";

import { generateRandomPolynomial, Metadata } from "../src/index";

const PRIVATE_KEY = bytesToHex(generatePrivate());

describe("Metadata", function () {
  it("#should serialize and deserialize into JSON seamlessly", async function () {
    const privKey = PRIVATE_KEY;
    const privKeyBN = BigInt(`0x${privKey}`);
    // create a random poly and respective shares
    const shareIndexes = [1n, 2n];
    for (let i = 1; i <= 2; i += 1) {
      let ran = generatePrivate();

      while (ran < 2) {
        ran = generatePrivate();
      }
      shareIndexes.push(bytesToNumberBE(ran));
    }
    const poly = generateRandomPolynomial(1, privKeyBN);
    const shares = poly.generateShares(shareIndexes);
    const metadata = new Metadata(getPubKeyPoint(privKeyBN));
    metadata.addFromPolynomialAndShares(poly, shares);
    metadata.setGeneralStoreDomain("something", { test: "oh this is an object" });
    const serializedMetadata = stringify(metadata);
    const deserializedMetadata = Metadata.fromJSON(JSON.parse(serializedMetadata));
    const secondSerialization = stringify(deserializedMetadata);
    deepStrictEqual(serializedMetadata, secondSerialization, "serializedMetadata should be equal");
    const deserializedMetadata2 = Metadata.fromJSON(JSON.parse(secondSerialization));
    deepStrictEqual(deserializedMetadata2, deserializedMetadata, "metadata and deserializedMetadata should be equal");
  });
  it("#should serialize and deserialize into JSON with tkey store seamlessly", async function () {
    const privKey = PRIVATE_KEY;
    const privKeyBN = BigInt(`0x${privKey}`);
    // create a random poly and respective shares
    const shareIndexes = [1n, 2n];
    for (let i = 1; i <= 2; i += 1) {
      let ran = generatePrivate();
      while (ran < 2) {
        ran = generatePrivate();
      }
      shareIndexes.push(bytesToNumberBE(ran));
    }
    const poly = generateRandomPolynomial(1, privKeyBN);
    const shares = poly.generateShares(shareIndexes);
    const metadata = new Metadata(getPubKeyPoint(privKeyBN));
    metadata.addFromPolynomialAndShares(poly, shares);
    metadata.setTkeyStoreDomain("something", { test: "oh this is an object" });
    const serializedMetadata = stringify(metadata);
    const deserializedMetadata = Metadata.fromJSON(JSON.parse(serializedMetadata));
    const secondSerialization = stringify(deserializedMetadata);
    deepStrictEqual(serializedMetadata, secondSerialization, "serializedMetadata should be equal");
    const deserializedMetadata2 = Metadata.fromJSON(JSON.parse(secondSerialization));
    deepStrictEqual(deserializedMetadata2, deserializedMetadata, "metadata and deserializedMetadata should be equal");
  });
  it("#should serialize and deserialize into JSON with tkey store seamlessly 2", async function () {
    const privKey = PRIVATE_KEY;
    const privKeyBN = BigInt(`0x${privKey}`);
    // create a random poly and respective shares
    const shareIndexes = [1n, 2n];
    for (let i = 1; i <= 2; i += 1) {
      let ran = generatePrivate();
      while (ran < 2) {
        ran = generatePrivate();
      }
      shareIndexes.push(bytesToNumberBE(ran));
    }
    const poly = generateRandomPolynomial(1, privKeyBN);
    const shares = poly.generateShares(shareIndexes);
    const metadata = new Metadata(getPubKeyPoint(privKeyBN));
    metadata.addFromPolynomialAndShares(poly, shares);
    metadata.setScopedStore("something", { test: "oh this is an object" });
    const serializedMetadata = stringify(metadata);
    const deserializedMetadata = Metadata.fromJSON(JSON.parse(serializedMetadata));
    const secondSerialization = stringify(deserializedMetadata);
    deepStrictEqual(serializedMetadata, secondSerialization, "serializedMetadata should be equal");
    const deserializedMetadata2 = Metadata.fromJSON(JSON.parse(secondSerialization));
    deepStrictEqual(deserializedMetadata2, deserializedMetadata, "metadata and deserializedMetadata should be equal");
  });
});
