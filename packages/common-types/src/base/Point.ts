import { concatBytes, hexToBigInt, numberToBytesBE, secp256k1 } from "@toruslabs/metadata-helpers";

import { IPoint, StringifiedType } from "../baseTypes/commonTypes";

class Point implements IPoint {
  x: bigint;

  y: bigint;

  constructor(x: bigint, y: bigint) {
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
        return concatBytes([prefix, xBytes, yBytes]);
      }
      default:
        throw new Error("encoding doesnt exist in Point");
    }
  }

  toProjectivePoint() {
    return secp256k1.Point.fromAffine({ x: this.x, y: this.y });
  }

  toSEC1(compressed = false): Uint8Array {
    return this.toProjectivePoint().toBytes(compressed);
  }

  toJSON(): StringifiedType {
    return {
      x: this.x.toString(16),
      y: this.y.toString(16),
    };
  }

  toPointHex() {
    return {
      x: this.x.toString(16).padStart(64, "0"),
      y: this.y.toString(16).padStart(64, "0"),
    };
  }

  equals(p: Point): boolean {
    return this.x === p.x && this.y === p.y;
  }
}

export default Point;
