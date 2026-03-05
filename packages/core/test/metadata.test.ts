import { getPubKeyPoint } from "@tkey/common-types";
import { generatePrivate } from "@toruslabs/eccrypto";
import { bytesToHex, bytesToNumberBE } from "@toruslabs/metadata-helpers";
import stringify from "json-stable-stringify";
import { describe, expect, it } from "vitest";

import { generateRandomPolynomial, Metadata } from "../src/index";

const PRIVATE_KEY = bytesToHex(generatePrivate());

describe("Metadata", function () {
  it("#should serialize and deserialize into JSON seamlessly", async function () {
    const privKey = PRIVATE_KEY;
    const privKeyBN = BigInt(`0x${privKey}`);
    const shareIndexes = [1n, 2n];
    for (let i = 1; i <= 2; i += 1) {
      let ran = generatePrivate();
      while (bytesToNumberBE(ran) < 2) {
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
    expect(serializedMetadata).toStrictEqual(secondSerialization);
    const deserializedMetadata2 = Metadata.fromJSON(JSON.parse(secondSerialization));
    expect(deserializedMetadata2).toStrictEqual(deserializedMetadata);
  });
  it("#should serialize and deserialize into JSON with tkey store seamlessly", async function () {
    const privKey = PRIVATE_KEY;
    const privKeyBN = BigInt(`0x${privKey}`);
    const shareIndexes = [1n, 2n];
    for (let i = 1; i <= 2; i += 1) {
      let ran = generatePrivate();
      while (bytesToNumberBE(ran) < 2) {
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
    expect(serializedMetadata).toStrictEqual(secondSerialization);
    const deserializedMetadata2 = Metadata.fromJSON(JSON.parse(secondSerialization));
    expect(deserializedMetadata2).toStrictEqual(deserializedMetadata);
  });
  it("#should serialize and deserialize into JSON with tkey store seamlessly 2", async function () {
    const privKey = PRIVATE_KEY;
    const privKeyBN = BigInt(`0x${privKey}`);
    const shareIndexes = [1n, 2n];
    for (let i = 1; i <= 2; i += 1) {
      let ran = generatePrivate();
      while (bytesToNumberBE(ran) < 2) {
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
    expect(serializedMetadata).toStrictEqual(secondSerialization);
    const deserializedMetadata2 = Metadata.fromJSON(JSON.parse(secondSerialization));
    expect(deserializedMetadata2).toStrictEqual(deserializedMetadata);
  });
});
