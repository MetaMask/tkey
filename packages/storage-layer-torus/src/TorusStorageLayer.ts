import {
  bigIntReplacer,
  decrypt,
  encrypt,
  EncryptedMessage,
  getPubKeyECC,
  getPubKeyPoint,
  IServiceProvider,
  IStorageLayer,
  KEY_NOT_FOUND,
  ONE_KEY_DELETE_NONCE,
  ONE_KEY_NAMESPACE,
  prettyPrintError,
  StringifiedType,
  toPrivKeyECC,
  TorusStorageLayerAPIParams,
  TorusStorageLayerArgs,
} from "@tkey/common-types";
import { post } from "@toruslabs/http-helpers";
import {
  bytesToBase64,
  bytesToHex,
  bytesToUtf8,
  decodeBase64Url,
  encodeBase64Url,
  keccak256Bytes,
  secp256k1,
  utf8ToBytes,
} from "@toruslabs/metadata-helpers";
import stringify from "json-stable-stringify";

function signDataWithPrivKey(data: { timestamp: number }, privKey: bigint): string {
  const hash = keccak256Bytes(utf8ToBytes(stringify(data)));
  const sig = secp256k1.sign(hash, toPrivKeyECC(privKey), { prehash: false, format: "der" });
  return bytesToHex(sig);
}

class TorusStorageLayer implements IStorageLayer {
  enableLogging: boolean;

  hostUrl: string;

  storageLayerName: string;

  serverTimeOffset: number;

  constructor({ enableLogging = false, hostUrl = "http://localhost:5051", serverTimeOffset = 0 }: TorusStorageLayerArgs) {
    this.enableLogging = enableLogging;
    this.hostUrl = hostUrl;
    this.storageLayerName = "TorusStorageLayer";
    this.serverTimeOffset = serverTimeOffset;
  }

  static async serializeMetadataParamsInput(el: unknown, serviceProvider: IServiceProvider, privKey: bigint): Promise<unknown> {
    if (typeof el === "object") {
      // Allow using of special message as command, in which case, do not encrypt
      const obj = el as Record<string, unknown>;
      const isCommandMessage = obj.message === ONE_KEY_DELETE_NONCE;
      if (isCommandMessage) return obj.message;
    }

    // General case, encrypt message
    const msgBytes = utf8ToBytes(stringify(el, { replacer: bigIntReplacer }));
    let encryptedDetails: EncryptedMessage;
    if (privKey) {
      encryptedDetails = await encrypt(getPubKeyECC(privKey), msgBytes);
    } else {
      encryptedDetails = await serviceProvider.encrypt(msgBytes);
    }
    const serializedEncryptedDetails = encodeBase64Url(stringify(encryptedDetails));
    return serializedEncryptedDetails;
  }

  static fromJSON(value: StringifiedType): TorusStorageLayer {
    const { enableLogging, hostUrl, storageLayerName, serverTimeOffset = 0 } = value;
    if (storageLayerName !== "TorusStorageLayer") return undefined;
    return new TorusStorageLayer({ enableLogging, hostUrl, serverTimeOffset });
  }

  /**
   *  Get metadata for a key
   * @param privKey - If not provided, it will use service provider's share for decryption
   */
  async getMetadata<T>(params: { serviceProvider?: IServiceProvider; privKey?: bigint }): Promise<T> {
    const { serviceProvider, privKey } = params;
    const keyDetails = this.generateMetadataParams({}, serviceProvider, privKey);
    const metadataResponse = await post<{ message: string }>(`${this.hostUrl}/get`, keyDetails);
    // returns empty object if object
    if (metadataResponse.message === "") {
      return { message: KEY_NOT_FOUND } as T;
    }
    const encryptedMessage = JSON.parse(decodeBase64Url(metadataResponse.message));

    let decrypted: Uint8Array;
    if (privKey) {
      decrypted = await decrypt(toPrivKeyECC(privKey), encryptedMessage);
    } else {
      decrypted = await serviceProvider.decrypt(encryptedMessage);
    }

    return JSON.parse(bytesToUtf8(decrypted)) as T;
  }

  /**
   * Set Metadata for a key
   * @param input - data to post
   * @param privKey - If not provided, it will use service provider's share for encryption
   */
  async setMetadata<T>(params: { input: T; serviceProvider?: IServiceProvider; privKey?: bigint }): Promise<{ message: string }> {
    try {
      const { serviceProvider, privKey, input } = params;
      const metadataParams = this.generateMetadataParams(
        await TorusStorageLayer.serializeMetadataParamsInput(input, serviceProvider, privKey),
        serviceProvider,
        privKey
      );
      return await post<{ message: string }>(`${this.hostUrl}/set`, metadataParams);
    } catch (error: unknown) {
      const prettyError = await prettyPrintError(error);
      throw prettyError as Error;
    }
  }

  async setMetadataStream<T>(params: { input: Array<T>; serviceProvider?: IServiceProvider; privKey?: Array<bigint> }): Promise<{ message: string }> {
    try {
      const { serviceProvider, privKey, input } = params;
      const newInput = input;
      const finalMetadataParams = await Promise.all(
        newInput.map(async (el, i) =>
          this.generateMetadataParams(
            await TorusStorageLayer.serializeMetadataParamsInput(el, serviceProvider, privKey[i]),
            serviceProvider,
            privKey[i]
          )
        )
      );

      const FD = new FormData();
      finalMetadataParams.forEach((el, index) => {
        FD.append(index.toString(), JSON.stringify(el, bigIntReplacer));
      });
      const options: RequestInit = {
        mode: "cors",
        method: "POST",
        headers: {
          // don't set ContentType header here. it's handled in http-helpers
        },
      };

      const customOptions = {
        isUrlEncodedData: true,
        timeout: 600 * 1000, // 10 mins of timeout for excessive shares case
      };
      return await post<{ message: string }>(`${this.hostUrl}/bulk_set_stream`, FD, options, customOptions);
    } catch (error) {
      const prettyError = await prettyPrintError(error);
      throw prettyError as Error;
    }
  }

  generateMetadataParams(message: unknown, serviceProvider?: IServiceProvider, privKey?: bigint): TorusStorageLayerAPIParams {
    let sig: string;
    let pubX: string;
    let pubY: string;
    let namespace = "tkey";
    const setTKeyStore = {
      data: message,
      timestamp: Math.floor(this.serverTimeOffset + Date.now() / 1000).toString(16),
    };

    // Overwrite bulk_set to allow deleting nonce v2 together with creating tKey.
    // This is a workaround, a better solution is allow upstream API to set tableName/namespace of metadata params
    if (message === ONE_KEY_DELETE_NONCE) {
      namespace = ONE_KEY_NAMESPACE;
      setTKeyStore.data = "<deleted>";
    }

    const hash = keccak256Bytes(utf8ToBytes(stringify(setTKeyStore)));
    if (privKey) {
      const recoveredSig = secp256k1.sign(hash, toPrivKeyECC(privKey), { prehash: false, format: "recovered" });
      const sigWithV = new Uint8Array(65);
      sigWithV.set(recoveredSig.slice(1, 65), 0); // r + s
      sigWithV[64] = recoveredSig[0]; // v
      sig = bytesToBase64(sigWithV);
      const pubK = getPubKeyPoint(privKey);
      pubX = pubK.x.toString(16);
      pubY = pubK.y.toString(16);
    } else {
      const point = serviceProvider.retrievePubKeyPoint();
      sig = serviceProvider.sign(hash);
      pubX = point.x.toString(16);
      pubY = point.y.toString(16);
    }
    return {
      pub_key_X: pubX,
      pub_key_Y: pubY,
      set_data: setTKeyStore,
      signature: sig,
      namespace,
    };
  }

  async acquireWriteLock(params: { serviceProvider?: IServiceProvider; privKey?: bigint }): Promise<{ status: number; id?: string }> {
    const { serviceProvider, privKey } = params;
    if (!serviceProvider && !privKey) throw new Error("acquireWriteLock: either privKey or serviceProvider must be provided");
    const data = {
      timestamp: Math.floor(this.serverTimeOffset + Date.now() / 1000),
    };

    let signature: string;
    let key: string;
    if (privKey) {
      signature = signDataWithPrivKey(data, privKey);
      key = bytesToHex(getPubKeyECC(privKey));
    } else {
      signature = serviceProvider.sign(keccak256Bytes(utf8ToBytes(stringify(data))));
      key = bytesToHex(serviceProvider.retrievePubKey("ecc"));
    }
    const metadataParams = {
      key,
      data,
      signature,
    };
    return post<{ status: number; id?: string }>(`${this.hostUrl}/acquireLock`, metadataParams);
  }

  async releaseWriteLock(params: { id: string; serviceProvider?: IServiceProvider; privKey?: bigint }): Promise<{ status: number }> {
    const { serviceProvider, privKey, id } = params;
    if (!serviceProvider && !privKey) throw new Error("releaseWriteLock: either privKey or serviceProvider must be provided");
    const data = {
      timestamp: Math.floor(this.serverTimeOffset + Date.now() / 1000),
    };

    let signature: string;
    let key: string;
    if (privKey) {
      signature = signDataWithPrivKey(data, privKey);
      key = bytesToHex(getPubKeyECC(privKey));
    } else {
      signature = serviceProvider.sign(keccak256Bytes(utf8ToBytes(stringify(data))));
      key = bytesToHex(serviceProvider.retrievePubKey("ecc"));
    }
    const metadataParams = {
      key,
      data,
      signature,
      id,
    };
    return post<{ status: number; id?: string }>(`${this.hostUrl}/releaseLock`, metadataParams);
  }

  toJSON(): StringifiedType {
    return {
      enableLogging: this.enableLogging,
      hostUrl: this.hostUrl,
      storageLayerName: this.storageLayerName,
    };
  }
}

export default TorusStorageLayer;
