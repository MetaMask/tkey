import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberBE, concatBytes, equalBytes, numberToBytesBE } from "@noble/curves/utils.js";
import { generateID, IPrivateKeyFormat, IPrivateKeyStore } from "@tkey/common-types";

export class ED25519Format implements IPrivateKeyFormat {
  privateKey: bigint;

  type: string;

  constructor(privateKey: bigint) {
    this.privateKey = privateKey;
    this.type = "ed25519";
  }

  validatePrivateKey(privateKey: bigint): boolean {
    try {
      const keyBytes = numberToBytesBE(privateKey, 64);
      const seed = keyBytes.slice(0, 32);
      const storedPubKey = keyBytes.slice(32);
      const derivedPubKey = ed25519.getPublicKey(seed);
      return equalBytes(derivedPubKey, storedPubKey);
    } catch {
      return false;
    }
  }

  createPrivateKeyStore(privateKey?: bigint): IPrivateKeyStore {
    let privKey: bigint;
    if (!privateKey) {
      const seed = ed25519.utils.randomSecretKey();
      const pubKey = ed25519.getPublicKey(seed);
      privKey = bytesToNumberBE(concatBytes(seed, pubKey));
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
