import { getPublic } from "@toruslabs/eccrypto";
import { hexToBytes } from "@toruslabs/metadata-helpers";
import BN from "bn.js";
import type { curve, ec } from "elliptic";

import { BNString } from "../baseTypes/commonTypes";
import { secp256k1 } from "../utils";
import Point from "./Point";

// These functions are here because BN can't be extended
export const toPrivKeyEC = (bn: BN): ec.KeyPair => secp256k1.keyFromPrivate(bn.toString("hex", 64));

export const toPrivKeyECC = (bn: BNString): Uint8Array => {
  const tmp = new BN(bn, "hex");
  return hexToBytes(tmp.toString("hex", 64));
};

export const getPubKeyEC = (bn: BN): curve.base.BasePoint => secp256k1.keyFromPrivate(bn.toString("hex", 64)).getPublic();

export const getPubKeyECC = (bn: BN): Uint8Array => getPublic(Buffer.from(toPrivKeyECC(bn)));

export const getPubKeyPoint = (bn: BN): Point => {
  const pubKeyEc = getPubKeyEC(bn);
  return new Point(pubKeyEc.getX().toString("hex"), pubKeyEc.getY().toString("hex"));
};
