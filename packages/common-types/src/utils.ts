import { serializeError } from "@toruslabs/customauth";
import { decrypt as ecDecrypt, encrypt as ecEncrypt } from "@toruslabs/eccrypto";
import { add0x, bytesToHex, bytesToNumberBE, getChecksumAddress, hexToBytes, keccak256, secp256k1 } from "@toruslabs/metadata-helpers";

import { EncryptedMessage } from "./baseTypes/commonTypes";

/** Returns 32 random bytes suitable for use as a secp256k1 private key. */
export function generatePrivate(): Uint8Array {
  return secp256k1.utils.randomSecretKey();
}

export async function encrypt(publicKey: Uint8Array, msg: Uint8Array): Promise<EncryptedMessage> {
  const encryptedDetails = await ecEncrypt(publicKey, msg);

  return {
    ciphertext: bytesToHex(encryptedDetails.ciphertext),
    ephemPublicKey: bytesToHex(encryptedDetails.ephemPublicKey),
    iv: bytesToHex(encryptedDetails.iv),
    mac: bytesToHex(encryptedDetails.mac),
  };
}

export async function decrypt(privKey: Uint8Array, msg: EncryptedMessage): Promise<Uint8Array> {
  return ecDecrypt(privKey, {
    ciphertext: hexToBytes(msg.ciphertext),
    ephemPublicKey: hexToBytes(msg.ephemPublicKey),
    iv: hexToBytes(msg.iv),
    mac: hexToBytes(msg.mac),
  });
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

export function bigIntReplacer(this: unknown, _key: string | number, value: unknown): unknown {
  return typeof value === "bigint" ? value.toString(16) : value;
}

export function generateAddressFromPublicKey(publicKey: Uint8Array): string {
  const pubKeyHash = keccak256(publicKey);
  const ethAddressLower = add0x(pubKeyHash.slice(-40));
  return getChecksumAddress(ethAddressLower);
}

export function generatePrivateExcludingIndexes(shareIndexes: bigint[]): bigint {
  const key = bytesToNumberBE(generatePrivate());
  if (shareIndexes.find((el) => el === key)) {
    return generatePrivateExcludingIndexes(shareIndexes);
  }
  return key;
}

export const KEY_NOT_FOUND = "KEY_NOT_FOUND";
export const SHARE_DELETED = "SHARE_DELETED";

export function derivePubKeyXFromPolyID(polyID: string): string {
  return polyID.split("|")[0].slice(2);
}

export function generateID(): string {
  // Math.random should be unique because of its seeding algorithm.
  // Convert it to base 36 (numbers + letters), and grab the first 9 characters
  // after the decimal.
  return `${Math.random().toString(36).substr(2, 9)}`;
}
