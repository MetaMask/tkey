import { serializeError } from "@toruslabs/customauth";
import { decrypt as ecDecrypt, encrypt as ecEncrypt, generatePrivate } from "@toruslabs/eccrypto";
import { bytesToHex, hexToBytes } from "@toruslabs/metadata-helpers";
import { keccak256, toChecksumAddress } from "@toruslabs/torus.js";
import BN from "bn.js";
import { ec as EC } from "elliptic";

import { EncryptedMessage } from "./baseTypes/commonTypes";

export const secp256k1 = new EC("secp256k1");

// eccrypto boundary: convert Uint8Array <-> Buffer at the edge
export async function encrypt(publicKey: Uint8Array, msg: Uint8Array): Promise<EncryptedMessage> {
  const encryptedDetails = await ecEncrypt(Buffer.from(publicKey), Buffer.from(msg));

  return {
    ciphertext: bytesToHex(new Uint8Array(encryptedDetails.ciphertext)),
    ephemPublicKey: bytesToHex(new Uint8Array(encryptedDetails.ephemPublicKey)),
    iv: bytesToHex(new Uint8Array(encryptedDetails.iv)),
    mac: bytesToHex(new Uint8Array(encryptedDetails.mac)),
  };
}

export async function decrypt(privKey: Uint8Array, msg: EncryptedMessage): Promise<Uint8Array> {
  const bufferEncDetails = {
    ciphertext: Buffer.from(hexToBytes(msg.ciphertext)),
    ephemPublicKey: Buffer.from(hexToBytes(msg.ephemPublicKey)),
    iv: Buffer.from(hexToBytes(msg.iv)),
    mac: Buffer.from(hexToBytes(msg.mac)),
  };

  const result = await ecDecrypt(Buffer.from(privKey), bufferEncDetails);
  return new Uint8Array(result);
}

export function isEmptyObject(obj: unknown): boolean {
  return Object.keys(obj).length === 0 && obj.constructor === Object;
}

export const isErrorObj = (err: unknown): boolean => err && (err as Error).stack && (err as Error).message !== "";

export async function prettyPrintError(error: unknown): Promise<Error> {
  if (isErrorObj(error)) {
    return error as Error;
  }
  return serializeError(error);
}

export function generateAddressFromPublicKey(publicKey: Uint8Array): string {
  const ethAddressLower = `0x${keccak256(publicKey).slice(64 - 38)}`;
  return toChecksumAddress(ethAddressLower);
}

export function normalize(input: number | string): string {
  if (!input) {
    return undefined;
  }
  let hexString;

  if (typeof input === "number") {
    hexString = input.toString(16);
    if (hexString.length % 2) {
      hexString = `0${hexString}`;
    }
  }

  if (typeof input === "string") {
    hexString = input.toLowerCase();
  }

  return `0x${hexString}`;
}

export function generatePrivateExcludingIndexes(shareIndexes: Array<BN>): BN {
  const key = new BN(generatePrivate());
  if (shareIndexes.find((el) => el.eq(key))) {
    return generatePrivateExcludingIndexes(shareIndexes);
  }
  return key;
}

export const KEY_NOT_FOUND = "KEY_NOT_FOUND";
export const SHARE_DELETED = "SHARE_DELETED";

export function derivePubKeyXFromPolyID(polyID: string): string {
  return polyID.split("|")[0].slice(2);
}

export function stripHexPrefix(str: string): string {
  if (str.slice(0, 2) === "0x") return str.slice(2);
  return str;
}

export function generateID(): string {
  // Math.random should be unique because of its seeding algorithm.
  // Convert it to base 36 (numbers + letters), and grab the first 9 characters
  // after the decimal.
  return `${Math.random().toString(36).substr(2, 9)}`;
}
