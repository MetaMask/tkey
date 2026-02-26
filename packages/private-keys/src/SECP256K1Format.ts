import { generateID, IPrivateKeyFormat, IPrivateKeyStore, secp256k1 } from "@tkey/common-types";
import BN from "bn.js";

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
  privateKey: BN;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ecParams: any;

  type: string;

  constructor(privateKey: BN) {
    this.privateKey = privateKey;
    this.ecParams = secp256k1.curve;
    this.type = "secp256k1n";
  }

  validatePrivateKey(privateKey: BN): boolean {
    return privateKey.cmp(this.ecParams.n) < 0 && !privateKey.isZero();
  }

  createPrivateKeyStore(privateKey?: BN): IPrivateKeyStore {
    let privKey: BN;
    if (!privateKey) {
      privKey = new BN(randomBytes(64));
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
