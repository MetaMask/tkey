import { generatePrivate } from "@toruslabs/eccrypto";
import { bytesToHex, bytesToNumberBE, secp256k1 } from "@toruslabs/metadata-helpers";
import { describe, expect, it } from "vitest";

import { getPubKeyPoint, Point, Polynomial } from "../src/base";

describe("polynomial", function () {
  it("#should polyEval indexes correctly", async function () {
    const polyArr = [5n, 2n];
    const poly = new Polynomial(polyArr);
    const result = poly.polyEval(1n);
    expect(result).toBe(7n);
  });
});

describe("Point", function () {
  it("#should encode into elliptic format on encode", async function () {
    const secret = bytesToNumberBE(generatePrivate());
    const point = getPubKeyPoint(secret);
    const result = point.toSEC1(true);
    expect(bytesToHex(result).slice(2)).toBe(point.x.toString(16).padStart(64, "0"));
  });

  it("#should decode into point for elliptic format compressed", async function () {
    const secret = bytesToNumberBE(generatePrivate());
    const point = getPubKeyPoint(secret);
    const result = point.toSEC1(true);
    expect(bytesToHex(result).slice(2)).toBe(point.x.toString(16).padStart(64, "0"));
    const key = secp256k1.Point.fromHex(bytesToHex(result)).toAffine();
    expect(point.x).toBe(key.x);
    expect(point.y).toBe(key.y);
  });

  it("#should decode into point for fromSEC1", async function () {
    const secret = bytesToNumberBE(generatePrivate());
    const point = getPubKeyPoint(secret);
    const result = point.toSEC1(true);
    expect(bytesToHex(result).slice(2)).toBe(point.x.toString(16).padStart(64, "0"));

    const key = Point.fromSEC1(bytesToHex(result));
    expect(point.x).toBe(key.x);
    expect(point.y).toBe(key.y);
  });
});
