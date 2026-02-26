import { invert, mod } from "@noble/curves/abstract/modular.js";
import { bytesToNumberBE } from "@noble/curves/utils.js";
import { generatePrivateExcludingIndexes, Point, Polynomial, secp256k1, Share } from "@tkey/common-types";

import CoreError from "./errors";

const N = secp256k1.Point.CURVE().n;

export function generatePrivateBigInt(): bigint {
  return bytesToNumberBE(secp256k1.utils.randomSecretKey());
}

const generateEmptyBigIntArray = (length: number): bigint[] => Array.from({ length }, () => 0n);

const denominator = (i: number, innerPoints: Point[]) => {
  let result = 1n;
  const xi = innerPoints[i].x;
  for (let j = innerPoints.length - 1; j >= 0; j -= 1) {
    if (i !== j) {
      const tmp = mod(xi - innerPoints[j].x, N);
      result = mod(result * tmp, N);
    }
  }
  return result;
};

const interpolationPoly = (i: number, innerPoints: Point[]): bigint[] => {
  let coefficients = generateEmptyBigIntArray(innerPoints.length);
  const d = denominator(i, innerPoints);
  if (d === 0n) {
    throw CoreError.default("Denominator for interpolationPoly is 0");
  }
  coefficients[0] = invert(d, N);
  for (let k = 0; k < innerPoints.length; k += 1) {
    const newCoefficients = generateEmptyBigIntArray(innerPoints.length);
    if (k !== i) {
      let j: number;
      if (k < i) {
        j = k + 1;
      } else {
        j = k;
      }
      j -= 1;
      for (; j >= 0; j -= 1) {
        newCoefficients[j + 1] = mod(newCoefficients[j + 1] + coefficients[j], N);
        const tmp = mod(innerPoints[k].x * coefficients[j], N);
        newCoefficients[j] = mod(newCoefficients[j] - tmp, N);
      }
      coefficients = newCoefficients;
    }
  }
  return coefficients;
};

const pointSort = (innerPoints: Point[]): Point[] => {
  const pointArrClone = [...innerPoints];
  pointArrClone.sort((a, b) => (a.x < b.x ? -1 : a.x > b.x ? 1 : 0));
  return pointArrClone;
};

const lagrange = (unsortedPoints: Point[]) => {
  const sortedPoints = pointSort(unsortedPoints);
  const polynomial = generateEmptyBigIntArray(sortedPoints.length);
  for (let i = 0; i < sortedPoints.length; i += 1) {
    const coefficients = interpolationPoly(i, sortedPoints);
    for (let k = 0; k < sortedPoints.length; k += 1) {
      const tmp = sortedPoints[i].y * coefficients[k];
      polynomial[k] = mod(polynomial[k] + tmp, N);
    }
  }
  return new Polynomial(polynomial);
};

export function lagrangeInterpolatePolynomial(points: Point[]): Polynomial {
  return lagrange(points);
}

export function lagrangeInterpolation(shares: bigint[], nodeIndex: bigint[]): bigint {
  if (shares.length !== nodeIndex.length) {
    throw CoreError.default("shares not equal to nodeIndex length in lagrangeInterpolation");
  }
  let secret = 0n;
  for (let i = 0; i < shares.length; i += 1) {
    let upper = 1n;
    let lower = 1n;
    for (let j = 0; j < shares.length; j += 1) {
      if (i !== j) {
        upper = mod(upper * -nodeIndex[j], N);
        const temp = mod(nodeIndex[i] - nodeIndex[j], N);
        lower = mod(lower * temp, N);
      }
    }
    let delta = mod(upper * invert(lower, N), N);
    delta = mod(delta * shares[i], N);
    secret = secret + delta;
  }
  return mod(secret, N);
}

export function generateRandomPolynomial(degree: number, secret?: bigint, deterministicShares?: Share[]): Polynomial {
  const actualS = secret !== undefined ? secret : generatePrivateExcludingIndexes([0n]);
  if (!deterministicShares) {
    const poly: bigint[] = [actualS];
    for (let i = 0; i < degree; i += 1) {
      const share = generatePrivateExcludingIndexes(poly);
      poly.push(share);
    }
    return new Polynomial(poly);
  }
  if (!Array.isArray(deterministicShares)) {
    throw CoreError.default("deterministic shares in generateRandomPolynomial should be an array");
  }

  if (deterministicShares.length > degree) {
    throw CoreError.default("deterministicShares in generateRandomPolynomial should be less or equal than degree to ensure an element of randomness");
  }
  const points: Record<string, Point> = {};
  deterministicShares.forEach((share) => {
    points[share.shareIndex.toString(16)] = new Point(share.shareIndex, share.share);
  });
  for (let i = 0; i < degree - deterministicShares.length; i += 1) {
    let shareIndex = generatePrivateExcludingIndexes([0n]);
    while (points[shareIndex.toString(16)] !== undefined) {
      shareIndex = generatePrivateExcludingIndexes([0n]);
    }
    points[shareIndex.toString(16)] = new Point(shareIndex, generatePrivateBigInt());
  }
  points["0"] = new Point(0n, actualS);
  return lagrangeInterpolatePolynomial(Object.values(points));
}

//  2 + 3x = y | secret for index 1 is 5 >>> g^5 is the commitment | now we have g^2, g^3 and 1, |
export function polyCommitmentEval(polyCommitments: Point[], index: bigint): Point {
  let shareCommitment = polyCommitments[0].toProjectivePoint();
  for (let i = 1; i < polyCommitments.length; i += 1) {
    const factor = mod(index ** BigInt(i), N);
    const e = polyCommitments[i].toProjectivePoint().multiply(factor);
    shareCommitment = shareCommitment.add(e);
  }
  const affine = shareCommitment.toAffine();
  return new Point(affine.x, affine.y);
}
