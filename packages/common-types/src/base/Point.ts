import { concatBytes, hexToBytes, numberToBytesBE } from "@noble/curves/utils.js";

import { IPoint, StringifiedType } from "../baseTypes/commonTypes";
import { secp256k1 } from "../utils";

export function hexToBigInt(s: string | null | undefined): bigint | null {
  if (s === null || s === undefined) return null;
  return s.length > 0 ? BigInt(`0x${s}`) : 0n;
}

class Point implements IPoint {
  x: bigint | null;

  y: bigint | null;

  constructor(x: bigint | null, y: bigint | null) {
    this.x = x;
    this.y = y;
  }

  static fromScalar(s: bigint): Point {
    const p = secp256k1.Point.BASE.multiply(s).toAffine();
    return new Point(p.x, p.y);
  }

  /**
   * @deprecated Use `fromSEC1` instead.
   */
  static fromCompressedPub(value: string): Point {
    return Point.fromSEC1(value);
  }

  static fromJSON(value: StringifiedType): Point {
    const { x, y } = value;
    return new Point(hexToBigInt(x), hexToBigInt(y));
  }

  static fromAffine(p: { x: bigint; y: bigint }): Point {
    return new Point(p.x, p.y);
  }

  static fromSEC1(encodedPoint: string): Point {
    if (encodedPoint.length === 2 && encodedPoint === "00") {
      return new Point(null, null);
    }

    const p = secp256k1.Point.fromHex(encodedPoint).toAffine();
    return new Point(p.x, p.y);
  }

  /**
   * @deprecated Use `toSEC1` instead.
   */
  encode(enc: string): Uint8Array {
    switch (enc) {
      case "arr": {
        const prefix = new Uint8Array([0x04]);
        const xBytes = numberToBytesBE(this.x, 32);
        const yBytes = numberToBytesBE(this.y, 32);
        return concatBytes(prefix, xBytes, yBytes);
      }
      case "elliptic-compressed": {
        return this.toSEC1(true);
      }
      default:
        throw new Error("encoding doesnt exist in Point");
    }
  }

  toProjectivePoint() {
    if (this.isIdentity()) {
      return secp256k1.Point.ZERO;
    }
    return secp256k1.Point.fromAffine({ x: this.x, y: this.y });
  }

  toSEC1(compressed = false): Uint8Array {
    if (this.isIdentity()) {
      return hexToBytes("00");
    }

    return this.toProjectivePoint().toBytes(compressed);
  }

  toJSON(): StringifiedType {
    return {
      x: this.x?.toString(16) ?? null,
      y: this.y?.toString(16) ?? null,
    };
  }

  toPointHex() {
    return {
      x: this.x.toString(16).padStart(64, "0"),
      y: this.y.toString(16).padStart(64, "0"),
    };
  }

  isIdentity(): boolean {
    return this.x === null && this.y === null;
  }

  equals(p: Point): boolean {
    if (this.isIdentity()) {
      return p.isIdentity();
    }
    return this.x === p.x && this.y === p.y;
  }
}

export default Point;
