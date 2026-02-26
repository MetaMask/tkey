import { mod } from "@noble/curves/abstract/modular.js";

import { ISerializable, PolynomialID, StringifiedType } from "../baseTypes/commonTypes";
import { secp256k1 } from "../utils";
import { getPubKeyPoint } from "./BNUtils";
import Point, { hexToBigInt } from "./Point";
import PublicPolynomial from "./PublicPolynomial";
import Share from "./Share";

// @flow
export type ShareMap = {
  [x: string]: Share;
};

const N = secp256k1.CURVE.n;

class Polynomial implements ISerializable {
  polynomial: bigint[];

  publicPolynomial: PublicPolynomial;

  constructor(polynomial: bigint[]) {
    this.polynomial = polynomial;
  }

  static fromJSON(value: StringifiedType): Polynomial {
    const { polynomial } = value;
    return new Polynomial(polynomial.map((x: string) => hexToBigInt(x)));
  }

  getThreshold(): number {
    return this.polynomial.length;
  }

  polyEval(x: bigint): bigint {
    let xi = x;
    let sum = this.polynomial[0];
    for (let i = 1; i < this.polynomial.length; i += 1) {
      const tmp = xi * this.polynomial[i];
      sum = mod(sum + tmp, N);
      xi = mod(xi * x, N);
    }
    return sum;
  }

  generateShares(shareIndexes: bigint[]): ShareMap {
    const shares: ShareMap = {};
    for (let x = 0; x < shareIndexes.length; x += 1) {
      const idx = shareIndexes[x];
      shares[idx.toString(16)] = new Share(idx, this.polyEval(idx));
    }
    return shares;
  }

  getPublicPolynomial(): PublicPolynomial {
    const polynomialCommitments: Point[] = [];
    for (let i = 0; i < this.polynomial.length; i += 1) {
      polynomialCommitments.push(getPubKeyPoint(this.polynomial[i]));
    }
    this.publicPolynomial = new PublicPolynomial(polynomialCommitments);
    return this.publicPolynomial;
  }

  getPolynomialID(): PolynomialID {
    return this.publicPolynomial.polynomialId;
  }

  toJSON(): StringifiedType {
    return {
      polynomial: this.polynomial.map((x) => x.toString(16)),
    };
  }
}

export default Polynomial;
