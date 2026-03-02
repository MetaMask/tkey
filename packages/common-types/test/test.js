import { bytesToNumberBE } from "@noble/curves/utils.js";
import { generatePrivate } from "@toruslabs/eccrypto";
import { bytesToHex } from "@toruslabs/metadata-helpers";
import { fail } from "assert";

import { getPubKeyPoint, Point, Polynomial } from "../src/base";
import { secp256k1 } from "../src/utils";

describe("polynomial", function () {
  it("#should polyEval indexes correctly", async function () {
    const polyArr = [5n, 2n];
    const poly = new Polynomial(polyArr);
    const result = poly.polyEval(1n);
    if (result !== 7n) {
      fail("poly result should equal 7");
    }
  });
});

describe("Point", function () {
  it("#should encode into elliptic format on encode", async function () {
    const secret = bytesToNumberBE(generatePrivate());
    const point = getPubKeyPoint(secret);
    const result = point.toSEC1(true);
    if (bytesToHex(result).slice(2) !== point.x.toString(16).padStart(64, "0")) {
      fail(`elliptic format x should be equal ${secret} ${bytesToHex(result)} ${point.x.toString(16)} ${secret % secp256k1.Point.CURVE().n}`);
    }
  });

  it("#should decode into point for elliptic format compressed", async function () {
    const secret = bytesToNumberBE(generatePrivate());
    const point = getPubKeyPoint(secret);
    const result = point.toSEC1(true);
    if (bytesToHex(result).slice(2) !== point.x.toString(16).padStart(64, "0")) {
      fail("elliptic format x should be equal");
    }
    const key = secp256k1.Point.fromHex(bytesToHex(result)).toAffine();
    if (point.x !== key.x) {
      fail(" x should be equal");
    }
    if (point.y !== key.y) {
      fail(" x should be equal");
    }
  });

  it("#should decode into point for fromSEC1", async function () {
    const secret = bytesToNumberBE(generatePrivate());
    const point = getPubKeyPoint(secret);
    const result = point.toSEC1(true);
    if (bytesToHex(result).slice(2) !== point.x.toString(16).padStart(64, "0")) {
      fail("elliptic format x should be equal");
    }

    const key = Point.fromSEC1(bytesToHex(result));
    if (point.x !== key.x) {
      fail(" x should be equal");
    }
    if (point.y !== key.y) {
      fail(" x should be equal");
    }
  });
});
