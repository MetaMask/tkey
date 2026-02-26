import { getPubKeyPoint, Polynomial } from "@tkey/common-types";
import { generatePrivate } from "@toruslabs/eccrypto";
import { fail } from "assert";
import { bytesToNumberBE } from "@noble/curves/utils.js";

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
    if (expectedShareCommit1.x !== shareCommit1.x) {
      fail("expected share commitment1 should equal share commitment");
    }
    if (expectedShareCommit2.x !== shareCommit2.x) {
      fail("expected share commitment2 should equal share commitment");
    }
  });
  it("#should polyCommitmentEval random poly correctly", async function () {
    const degree = Math.floor(Math.random() * (50 - 1)) + 1;
    const poly = generateRandomPolynomial(degree);
    const publicPoly = poly.getPublicPolynomial();
    const expectedShareCommitment = [];
    const shareCommitment = [];
    for (let i = 0; i < 10; i += 1) {
      const shareIndex = bytesToNumberBE(generatePrivate());
      expectedShareCommitment.push(getPubKeyPoint(poly.polyEval(shareIndex)));
      shareCommitment.push(polyCommitmentEval(publicPoly.polynomialCommitments, shareIndex));
    }
    expectedShareCommitment.forEach(function (expected, i) {
      if (shareCommitment[i].x !== expected.x) {
        fail("poly result should equal hardcoded poly");
      }
    });
  });
});
