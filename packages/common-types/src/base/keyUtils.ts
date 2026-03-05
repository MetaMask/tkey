import { getPublic } from "@toruslabs/eccrypto";
import { numberToBytesBE, secp256k1 } from "@toruslabs/metadata-helpers";

import Point from "./Point";

export const toPrivKeyECC = (s: bigint): Uint8Array => {
  return numberToBytesBE(s, 32);
};

export const getPubKeyECC = (s: bigint): Uint8Array => getPublic(toPrivKeyECC(s));

export const getPubKeyPoint = (s: bigint): Point => {
  const p = secp256k1.Point.BASE.multiply(s).toAffine();
  return new Point(p.x, p.y);
};
