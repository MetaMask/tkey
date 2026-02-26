import { generateID, IPrivateKeyFormat, IPrivateKeyStore } from "@tkey/common-types";
import { base64ToBytes, bytesToBase64, hexToBytes } from "@toruslabs/metadata-helpers";
import nacl from "@toruslabs/tweetnacl-js";
import BN from "bn.js";

export class ED25519Format implements IPrivateKeyFormat {
  privateKey: BN;

  type: string;

  constructor(privateKey: BN) {
    this.privateKey = privateKey;
    this.type = "ed25519";
  }

  validatePrivateKey(privateKey: BN): boolean {
    // Validation as per
    // https://github.com/solana-labs/solana-web3.js/blob/e1567ab/src/keypair.ts#L65
    try {
      const secretKey = bytesToBase64(hexToBytes(privateKey.toString("hex")));
      const keypair = nacl.sign.keyPair.fromSecretKey(base64ToBytes(secretKey));
      const encoder = new TextEncoder();
      const signData = encoder.encode("@solana/web3.js-validation-v1");
      const signature = nacl.sign.detached(signData, keypair.secretKey);
      if (nacl.sign.detached.verify(signData, signature, keypair.publicKey)) {
        return true;
      }
    } catch {
      return false;
    }
    return false;
  }

  createPrivateKeyStore(privateKey?: BN): IPrivateKeyStore {
    let privKey: BN;
    if (!privateKey) {
      privKey = new BN(nacl.sign.keyPair().secretKey);
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
