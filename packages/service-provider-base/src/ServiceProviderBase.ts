import {
  decrypt as decryptUtils,
  encrypt as encryptUtils,
  EncryptedMessage,
  getPubKeyECC,
  IServiceProvider,
  PubKeyType,
  ServiceProviderArgs,
  StringifiedType,
  toPrivKeyECC,
} from "@tkey/common-types";
import { bytesToBase64, derivePubKey, numberToBytesBE, secp256k1 } from "@toruslabs/metadata-helpers";

class ServiceProviderBase implements IServiceProvider {
  enableLogging: boolean;

  // For easy serialization
  postboxKey: bigint;

  serviceProviderName: string;

  migratableKey: bigint | null = null;

  constructor({ enableLogging = false, postboxKey }: ServiceProviderArgs) {
    this.enableLogging = enableLogging;
    this.postboxKey = postboxKey != null ? BigInt(`0x${postboxKey}`) : 0n;
    this.serviceProviderName = "ServiceProviderBase";
  }

  static fromJSON(value: StringifiedType): IServiceProvider {
    const { enableLogging, postboxKey, serviceProviderName } = value;
    if (serviceProviderName !== "ServiceProviderBase") return undefined;

    return new ServiceProviderBase({ enableLogging, postboxKey });
  }

  async encrypt(msg: Uint8Array): Promise<EncryptedMessage> {
    const publicKey = this.retrievePubKey("ecc");
    return encryptUtils(publicKey, msg);
  }

  async decrypt(msg: EncryptedMessage): Promise<Uint8Array> {
    return decryptUtils(numberToBytesBE(this.postboxKey, 32), msg);
  }

  retrievePubKeyPoint(): { x: bigint; y: bigint } {
    const pt = derivePubKey(secp256k1, this.postboxKey);
    return { x: pt.x, y: pt.y };
  }

  retrievePubKey(type: PubKeyType): Uint8Array {
    if (type === "ecc") {
      return getPubKeyECC(this.postboxKey);
    }
    throw new Error("Unsupported pub key type");
  }

  sign(msg: Uint8Array): string {
    const recoveredSig = secp256k1.sign(msg, toPrivKeyECC(this.postboxKey), { prehash: false, format: "recovered" });
    const sigWithV = new Uint8Array(65);
    sigWithV.set(recoveredSig.slice(1, 65), 0); // r + s
    sigWithV[64] = recoveredSig[0]; // v
    return bytesToBase64(sigWithV);
  }

  toJSON(): StringifiedType {
    return {
      enableLogging: this.enableLogging,
      postboxKey: this.postboxKey.toString(16),
      serviceProviderName: this.serviceProviderName,
    };
  }
}

export default ServiceProviderBase;
