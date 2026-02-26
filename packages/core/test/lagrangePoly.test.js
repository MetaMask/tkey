import { Point, Polynomial } from "@tkey/common-types";
import { generatePrivate } from "@toruslabs/eccrypto";
import { fail } from "assert";
import { bytesToNumberBE } from "@noble/curves/utils.js";

import { generateRandomPolynomial, lagrangeInterpolatePolynomial } from "../src/index";

describe("lagrangeInterpolatePolynomial", function () {
  it("#should interpolate basic poly correctly", async function () {
    const polyArr = [5n, 2n];
    const poly = new Polynomial(polyArr);
    const share1 = poly.polyEval(1n);
    const share2 = poly.polyEval(2n);
    const resultPoly = lagrangeInterpolatePolynomial([new Point(1n, share1), new Point(2n, share2)]);
    if (polyArr[0] !== resultPoly.polynomial[0]) {
      fail("poly result should equal hardcoded poly");
    }
    if (polyArr[1] !== resultPoly.polynomial[1]) {
      fail("poly result should equal hardcoded poly");
    }
  });
  it("#should interpolate random poly correctly", async function () {
    const degree = Math.floor(Math.random() * (50 - 1)) + 1;
    const poly = generateRandomPolynomial(degree);
    const pointArr = [];
    for (let i = 0; i < degree + 1; i += 1) {
      const shareIndex = bytesToNumberBE(generatePrivate());
      pointArr.push(new Point(shareIndex, poly.polyEval(shareIndex)));
    }
    const resultPoly = lagrangeInterpolatePolynomial(pointArr);
    resultPoly.polynomial.forEach(function (coeff, i) {
      if (poly.polynomial[i] !== coeff) {
        fail("poly result should equal hardcoded poly");
      }
    });
  });
});
