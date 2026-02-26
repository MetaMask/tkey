import { bytesToHex } from "@noble/curves/utils.js";

import { ISerializable, PolynomialID, StringifiedType } from "../baseTypes/commonTypes";
import Point from "./Point";

class PublicPolynomial implements ISerializable {
  polynomialCommitments: Point[];

  polynomialId: PolynomialID;

  constructor(polynomialCommitments: Point[]) {
    this.polynomialCommitments = polynomialCommitments;
  }

  static fromJSON(value: StringifiedType): PublicPolynomial {
    const points: Point[] = value.polynomialCommitments.map((x: StringifiedType) => Point.fromJSON(x));
    return new PublicPolynomial(points);
  }

  getThreshold(): number {
    return this.polynomialCommitments.length;
  }

  getPolynomialID(): PolynomialID {
    let idSeed = "";
    for (let i = 0; i < this.polynomialCommitments.length; i += 1) {
      let nextChunk = bytesToHex(this.polynomialCommitments[i].toSEC1(true));
      if (i !== 0) {
        nextChunk = `|${nextChunk}`;
      }
      idSeed += nextChunk;
    }
    this.polynomialId = idSeed;
    return this.polynomialId;
  }

  toJSON(): StringifiedType {
    return {
      polynomialCommitments: this.polynomialCommitments,
    };
  }
}

// @flow
export type PublicPolynomialMap = {
  [polynomialID: string]: PublicPolynomial;
};

export default PublicPolynomial;
