import {
  BNString,
  decrypt as decryptUtils,
  encrypt as encryptUtils,
  EncryptedMessage,
  getPubKeyECC,
  getPubKeyPoint,
  IServiceProvider,
  PubKeyType,
  secp256k1,
  ServiceProviderArgs,
  StringifiedType,
  toPrivKeyECC,
} from "@tkey/common-types";
import { bytesToBase64, hexToBytes } from "@toruslabs/metadata-helpers";

class ServiceProviderBase implements IServiceProvider {
  enableLogging: boolean;

  // For easy serialization
  postboxKey: bigint;

  serviceProviderName: string;

  migratableKey: bigint | null = null;

  constructor({ enableLogging = false, postboxKey }: ServiceProviderArgs) {
    this.enableLogging = enableLogging;
    this.postboxKey = BigInt(`0x${postboxKey}`);
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
    return decryptUtils(toPrivKeyECC(this.postboxKey), msg);
  }

  retrievePubKeyPoint(): { x: bigint; y: bigint } {
    const pt = getPubKeyPoint(this.postboxKey);
    return { x: pt.x, y: pt.y };
  }

  retrievePubKey(type: PubKeyType): Uint8Array {
    if (type === "ecc") {
      return getPubKeyECC(this.postboxKey);
    }
    throw new Error("Unsupported pub key type");
  }

  sign(msg: BNString): string {
    const msgHex = typeof msg === "bigint" ? msg.toString(16) : msg;
    const sig = secp256k1.sign(msgHex, toPrivKeyECC(this.postboxKey), { prehash: false });
    const rHex = sig.r.toString(16).padStart(64, "0");
    const sHex = sig.s.toString(16).padStart(64, "0");
    return bytesToBase64(hexToBytes(rHex + sHex + "00"));
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
