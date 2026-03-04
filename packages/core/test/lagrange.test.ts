import { bytesToNumberBE } from "@noble/curves/utils.js";
import { Polynomial } from "@tkey/common-types";
import { generatePrivate } from "@toruslabs/eccrypto";
import { describe, it, expect } from "vitest";

import { generateRandomPolynomial, lagrangeInterpolation } from "../src/index";

describe("lagrange interpolate", function () {
  it("#should interpolate secret correctly", async function () {
    const polyArr = [5n, 2n];
    const poly = new Polynomial(polyArr);
    const share1 = poly.polyEval(1n);
    const share2 = poly.polyEval(2n);
    const key = lagrangeInterpolation([share1, share2], [1n, 2n]);
    expect(key).toBe(5n);
  });
  it("#should interpolate random secrets correctly", async function () {
    const degree = Math.ceil(Math.random() * 10);
    const secret = bytesToNumberBE(generatePrivate());
    const poly = generateRandomPolynomial(degree, secret);
    const shares = [];
    const indexes = [];
    for (let i = 1; i <= degree + 1; i += 1) {
      indexes.push(BigInt(i));
      shares.push(poly.polyEval(BigInt(i)));
    }
    const key = lagrangeInterpolation(shares, indexes);
    expect(key).toBe(secret);
  });
});
