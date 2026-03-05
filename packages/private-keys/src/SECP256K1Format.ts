import { generateID, IPrivateKeyFormat, IPrivateKeyStore } from "@tkey/common-types";
import { bytesToNumberBE, secp256k1 } from "@toruslabs/metadata-helpers";

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
      privKey = bytesToNumberBE(secp256k1.utils.randomSecretKey());
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
