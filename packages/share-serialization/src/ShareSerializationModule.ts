import { IModule, ITKeyApi } from "@tkey/common-types";

import { english } from "./english";
import ShareSerializationError from "./errors";
import { entropyToMnemonic, mnemonicToEntropy } from "./utils";

export const SHARE_SERIALIZATION_MODULE_NAME = "shareSerialization";

class ShareSerializationModule implements IModule {
  moduleName: string;

  tbSDK: ITKeyApi;

  constructor() {
    this.moduleName = SHARE_SERIALIZATION_MODULE_NAME;
  }

  static serializeMnemonic(share: bigint): string {
    return entropyToMnemonic(share.toString(16).padStart(64, "0"), english);
  }

  static deserializeMnemonic(share: string): bigint {
    return BigInt(`0x${mnemonicToEntropy(share, english)}`);
  }

  setModuleReferences(tbSDK: ITKeyApi): void {
    this.tbSDK = tbSDK;
    this.tbSDK._addShareSerializationMiddleware(this.serialize.bind(this), this.deserialize.bind(this));
  }

  async initialize(): Promise<void> {}

  async serialize(share: bigint, type: string): Promise<unknown> {
    if (type === "mnemonic") {
      return ShareSerializationModule.serializeMnemonic(share);
    }
    throw ShareSerializationError.typeNotSupported();
  }

  async deserialize(serializedShare: unknown, type: string): Promise<bigint> {
    if (type === "mnemonic") return ShareSerializationModule.deserializeMnemonic(serializedShare as string);
    throw ShareSerializationError.typeNotSupported();
  }
}

export default ShareSerializationModule;
