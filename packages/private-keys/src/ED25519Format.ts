import { bytesToNumberBE } from "@noble/curves/utils.js";
import { generateID, IPrivateKeyFormat, IPrivateKeyStore } from "@tkey/common-types";
import { base64ToBytes, bytesToBase64, hexToBytes } from "@toruslabs/metadata-helpers";
import nacl from "@toruslabs/tweetnacl-js";

export class ED25519Format implements IPrivateKeyFormat {
  privateKey: bigint;

  type: string;

  constructor(privateKey: bigint) {
    this.privateKey = privateKey;
    this.type = "ed25519";
  }

  validatePrivateKey(privateKey: bigint): boolean {
    // Validation as per
    // https://github.com/solana-labs/solana-web3.js/blob/e1567ab/src/keypair.ts#L65
    try {
      const secretKey = bytesToBase64(hexToBytes(privateKey.toString(16)));
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

  createPrivateKeyStore(privateKey?: bigint): IPrivateKeyStore {
    let privKey: bigint;
    if (!privateKey) {
      privKey = bytesToNumberBE(nacl.sign.keyPair().secretKey);
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
