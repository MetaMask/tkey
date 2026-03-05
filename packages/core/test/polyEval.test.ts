import { getPubKeyPoint, Point, Polynomial } from "@tkey/common-types";
import { generatePrivate } from "@toruslabs/eccrypto";
import { bytesToNumberBE } from "@toruslabs/metadata-helpers";
import { describe, expect, it } from "vitest";

import { generateRandomPolynomial, polyCommitmentEval } from "../src/index";

describe("polyCommitmentEval", function () {
  it("#should polyCommitmentEval basic poly correctly", async function () {
    const polyArr = [5n, 2n];
    const poly = new Polynomial(polyArr);
    const publicPoly = poly.getPublicPolynomial();
    const share1 = poly.polyEval(1n);
    const share2 = poly.polyEval(2n);
    const expectedShareCommit1 = getPubKeyPoint(share1);
    const expectedShareCommit2 = getPubKeyPoint(share2);
    const shareCommit1 = polyCommitmentEval(publicPoly.polynomialCommitments, 1n);
    const shareCommit2 = polyCommitmentEval(publicPoly.polynomialCommitments, 2n);
    expect(shareCommit1.x).toBe(expectedShareCommit1.x);
    expect(shareCommit2.x).toBe(expectedShareCommit2.x);
  });
  it("#should polyCommitmentEval random poly correctly", async function () {
    const degree = Math.floor(Math.random() * (50 - 1)) + 1;
    const poly = generateRandomPolynomial(degree);
    const publicPoly = poly.getPublicPolynomial();
    const expectedShareCommitment = [];
    const shareCommitment: Point[] = [];
    for (let i = 0; i < 10; i += 1) {
      const shareIndex = bytesToNumberBE(generatePrivate());
      expectedShareCommitment.push(getPubKeyPoint(poly.polyEval(shareIndex)));
      shareCommitment.push(polyCommitmentEval(publicPoly.polynomialCommitments, shareIndex));
    }
    expectedShareCommitment.forEach(function (expected, i) {
      expect(shareCommitment[i].x).toBe(expected.x);
    });
  });
});
