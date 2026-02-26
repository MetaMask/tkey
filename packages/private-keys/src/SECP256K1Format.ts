import { bytesToNumberBE } from "@noble/curves/utils.js";
import { generateID, IPrivateKeyFormat, IPrivateKeyStore, secp256k1 } from "@tkey/common-types";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const browserCrypto = global.crypto || (global as any).msCrypto || {};

function randomBytes(size: number): Uint8Array {
  if (typeof browserCrypto.getRandomValues === "undefined") {
    return new Uint8Array(browserCrypto.randomBytes(size));
  }
  const arr = new Uint8Array(size);
  browserCrypto.getRandomValues(arr);
  return arr;
}

export class SECP256K1Format implements IPrivateKeyFormat {
  privateKey: bigint;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ecParams: any;

  type: string;

  constructor(privateKey: bigint) {
    this.privateKey = privateKey;
    this.ecParams = secp256k1.Point.CURVE();
    this.type = "secp256k1n";
  }

  validatePrivateKey(privateKey: bigint): boolean {
    return privateKey < this.ecParams.n && privateKey !== 0n;
  }

  createPrivateKeyStore(privateKey?: bigint): IPrivateKeyStore {
    let privKey: bigint;
    if (!privateKey) {
      privKey = bytesToNumberBE(randomBytes(64));
    } else {
      if (!this.validatePrivateKey(privateKey)) {
        throw Error("Invalid Private Key");
      }
      privKey = privateKey;
    }
    return {
      id: generateID(),
      privateKey: privKey,
      type: this.type,
    };
  }
}
