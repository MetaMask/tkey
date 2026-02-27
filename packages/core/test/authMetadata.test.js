import { generatePrivateExcludingIndexes, getPubKeyPoint } from "@tkey/common-types";
import { generatePrivate } from "@toruslabs/eccrypto";
import { deepStrictEqual } from "assert";
import { bytesToHex, bytesToNumberBE } from "@noble/curves/utils.js";
import stringify from "json-stable-stringify";

import { AuthMetadata, generateRandomPolynomial, Metadata } from "../src/index";

const PRIVATE_KEY = bytesToHex(generatePrivate());

describe("AuthMetadata", function () {
  it("#should authenticate and  serialize and deserialize into JSON seamlessly", async function () {
    const privKeyBN = BigInt(`0x${PRIVATE_KEY}`);
    // create a random poly and respective shares
    const shareIndexes = [1n, 2n];
    shareIndexes.push(generatePrivateExcludingIndexes(shareIndexes));
    const poly = generateRandomPolynomial(1, privKeyBN);
    const shares = poly.generateShares(shareIndexes);
    const metadata = new Metadata(getPubKeyPoint(privKeyBN));
    metadata.addFromPolynomialAndShares(poly, shares);
    metadata.setGeneralStoreDomain("something", { test: "oh this is an object" });
    const a = new AuthMetadata(metadata, privKeyBN);
    const stringified = stringify(a);
    const metadataSerialized = Metadata.fromJSON(JSON.parse(stringify(metadata)));
    const final = AuthMetadata.fromJSON(JSON.parse(stringified));
    deepStrictEqual(final.metadata, metadataSerialized, "Must be equal");
  });
});
