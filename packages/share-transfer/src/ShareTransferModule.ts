import { bytesToNumberBE } from "@noble/curves/utils.js";
import {
  decrypt,
  encrypt,
  getPubKeyECC,
  getPubKeyPoint,
  hexToBigInt,
  IModule,
  ITKeyApi,
  ITkeyError,
  ShareStore,
  ShareStoreMap,
  ShareTransferStorePointerArgs,
  toPrivKeyECC,
} from "@tkey/common-types";
import { generatePrivate } from "@toruslabs/eccrypto";
import { bytesToUtf8, utf8ToBytes } from "@toruslabs/metadata-helpers";

import ShareTransferError from "./errors";
import ShareRequest from "./ShareRequest";
import ShareTransferStorePointer from "./ShareTransferStorePointer";
import { getClientIp } from "./utils";

export type ShareTransferStore = {
  [encPubKeyX: string]: ShareRequest;
};

export const SHARE_TRANSFER_MODULE_NAME = "shareTransfer";

class ShareTransferModule implements IModule {
  moduleName: string;

  tbSDK: ITKeyApi;

  currentEncKey: bigint;

  requestStatusCheckId: number;

  requestStatusCheckInterval: number;

  constructor() {
    this.moduleName = SHARE_TRANSFER_MODULE_NAME;
    this.requestStatusCheckInterval = 1000;
  }

  static refreshShareTransferMiddleware(
    generalStore: unknown,
    oldShareStores: ShareStoreMap,
    newShareStores: ShareStoreMap
  ): ShareTransferStorePointer {
    const numberOfOldShares = Object.keys(oldShareStores).length;
    const numberOfNewShares = Object.keys(newShareStores).length;

    // This is needed to avoid MIM during share deletion.
    if (numberOfNewShares <= numberOfOldShares) {
      const shareTransferStorePointer: ShareTransferStorePointer = { pointer: bytesToNumberBE(generatePrivate()) };
      return shareTransferStorePointer;
    }

    return generalStore as ShareTransferStorePointer;
  }

  setModuleReferences(tbSDK: ITKeyApi): void {
    this.tbSDK = tbSDK;
    this.tbSDK._addRefreshMiddleware(this.moduleName, ShareTransferModule.refreshShareTransferMiddleware);
  }

  setRequestStatusCheckInterval(interval: number): void {
    this.requestStatusCheckInterval = interval;
  }

  async initialize(): Promise<void> {
    const metadata = this.tbSDK.getMetadata();
    const rawShareTransferStorePointer = metadata.getGeneralStoreDomain(this.moduleName) as ShareTransferStorePointerArgs;
    let shareTransferStorePointer: ShareTransferStorePointer;
    if (!rawShareTransferStorePointer) {
      shareTransferStorePointer = { pointer: bytesToNumberBE(generatePrivate()) };
      metadata.setGeneralStoreDomain(this.moduleName, shareTransferStorePointer);
      // await this.tbSDK.syncShareMetadata(); // Requires threshold shares
      // OPTIMIZATION TO NOT SYNC METADATA TWICE ON INIT, WILL FAIL IF TKEY DOES NOT HAVE MODULE AS DEFAULT
    } else {
      shareTransferStorePointer = new ShareTransferStorePointer(rawShareTransferStorePointer);
    }
  }

  async requestNewShare(
    userAgent: string,
    availableShareIndexes: Array<string>,
    callback?: (err?: ITkeyError, shareStore?: ShareStore) => void
  ): Promise<string> {
    if (this.currentEncKey) throw ShareTransferError.requestExists(`${this.currentEncKey.toString(16)}`);
    this.currentEncKey = bytesToNumberBE(generatePrivate());
    const [newShareTransferStore, userIp] = await Promise.all([this.getShareTransferStore(), getClientIp()]);
    const encPubKeyX = getPubKeyPoint(this.currentEncKey).x.toString(16);
    newShareTransferStore[encPubKeyX] = new ShareRequest({
      encPubKey: getPubKeyECC(this.currentEncKey),
      encShareInTransit: undefined,
      availableShareIndexes,
      userAgent,
      userIp,
      timestamp: Date.now(),
    });
    await this.setShareTransferStore(newShareTransferStore);
    // watcher
    if (callback) {
      this.requestStatusCheckId = Number(
        setInterval(async () => {
          try {
            const latestShareTransferStore = await this.getShareTransferStore();
            if (!this.currentEncKey) throw ShareTransferError.missingEncryptionKey();
            if (latestShareTransferStore[encPubKeyX].encShareInTransit) {
              const shareStoreBuf = await decrypt(toPrivKeyECC(this.currentEncKey), latestShareTransferStore[encPubKeyX].encShareInTransit);
              const receivedShare = ShareStore.fromJSON(JSON.parse(bytesToUtf8(shareStoreBuf)));
              await this.tbSDK.inputShareStoreSafe(receivedShare, true);
              this._cleanUpCurrentRequest();
              callback(null, receivedShare);
            } else if (!latestShareTransferStore[encPubKeyX]) {
              this._cleanUpCurrentRequest();
              callback(ShareTransferError.userCancelledRequest());
            }
          } catch (error: unknown) {
            const err = error as ITkeyError;
            this._cleanUpCurrentRequest();
            callback(err);
          }
        }, this.requestStatusCheckInterval)
      );
    }
    return encPubKeyX;
  }

  async addCustomInfoToShareRequest(encPubKeyX: string, customInfo: string): Promise<void> {
    const shareTransferStore = await this.getShareTransferStore();
    if (!shareTransferStore[encPubKeyX]) throw ShareTransferError.missingEncryptionKey();
    shareTransferStore[encPubKeyX].customInfo = customInfo;
    await this.setShareTransferStore(shareTransferStore);
  }

  async lookForRequests(): Promise<Array<string>> {
    const shareTransferStore = await this.getShareTransferStore();
    return Object.keys(shareTransferStore);
  }

  async approveRequest(encPubKeyX: string, shareStore?: ShareStore): Promise<void> {
    const shareTransferStore = await this.getShareTransferStore();
    if (!shareTransferStore[encPubKeyX]) throw ShareTransferError.missingEncryptionKey();

    let shareBytes: Uint8Array;
    if (shareStore) {
      shareBytes = utf8ToBytes(JSON.stringify(shareStore));
    } else {
      const store = new ShareRequest(shareTransferStore[encPubKeyX]);
      const { availableShareIndexes } = store;
      const metadata = this.tbSDK.getMetadata();
      const latestPolynomial = metadata.getLatestPublicPolynomial();
      const latestPolynomialId = latestPolynomial.getPolynomialID();
      const indexes = metadata.getShareIndexesForPolynomial(latestPolynomialId);
      const filtered = indexes.filter((el) => !availableShareIndexes.includes(el));
      if (filtered.length === 0) throw ShareTransferError.default("no share index available to approve request");
      const share = this.tbSDK.outputShareStore(hexToBigInt(filtered[0]));
      shareBytes = utf8ToBytes(JSON.stringify(share));
    }
    const shareRequest = new ShareRequest(shareTransferStore[encPubKeyX]);
    shareTransferStore[encPubKeyX].encShareInTransit = await encrypt(shareRequest.encPubKey, shareBytes);
    await this.setShareTransferStore(shareTransferStore);
    this.currentEncKey = undefined;
  }

  async approveRequestWithShareIndex(encPubKeyX: string, shareIndex: bigint): Promise<void> {
    const deviceShare = this.tbSDK.outputShareStore(shareIndex);
    return this.approveRequest(encPubKeyX, deviceShare);
  }

  async getShareTransferStore(): Promise<ShareTransferStore> {
    const metadata = this.tbSDK.getMetadata();
    const shareTransferStorePointer = new ShareTransferStorePointer(metadata.getGeneralStoreDomain(this.moduleName) as ShareTransferStorePointerArgs);
    const storageLayer = this.tbSDK.getStorageLayer();
    return storageLayer.getMetadata<ShareTransferStore>({ privKey: shareTransferStorePointer.pointer });
  }

  async setShareTransferStore(shareTransferStore: ShareTransferStore): Promise<void> {
    const metadata = this.tbSDK.getMetadata();
    const shareTransferStorePointer = new ShareTransferStorePointer(metadata.getGeneralStoreDomain(this.moduleName) as ShareTransferStorePointerArgs);
    const storageLayer = this.tbSDK.getStorageLayer();
    await storageLayer.setMetadata({ input: shareTransferStore, privKey: shareTransferStorePointer.pointer });
  }

  async startRequestStatusCheck(encPubKeyX: string, deleteRequestAfterCompletion: boolean): Promise<ShareStore> {
    // watcher
    return new Promise((resolve, reject) => {
      this.requestStatusCheckId = Number(
        setInterval(async () => {
          try {
            const latestShareTransferStore = await this.getShareTransferStore();
            if (!this.currentEncKey) throw ShareTransferError.missingEncryptionKey();
            if (!latestShareTransferStore[encPubKeyX]) {
              this._cleanUpCurrentRequest();
              reject(ShareTransferError.userCancelledRequest());
            } else if (latestShareTransferStore[encPubKeyX].encShareInTransit) {
              const shareStoreBuf = await decrypt(toPrivKeyECC(this.currentEncKey), latestShareTransferStore[encPubKeyX].encShareInTransit);
              const receivedShare = ShareStore.fromJSON(JSON.parse(bytesToUtf8(shareStoreBuf)));
              await this.tbSDK.inputShareStoreSafe(receivedShare, true);
              if (deleteRequestAfterCompletion) {
                await this.deleteShareTransferStore(encPubKeyX);
              }
              this._cleanUpCurrentRequest();
              resolve(receivedShare);
            }
          } catch (err) {
            this._cleanUpCurrentRequest();
            reject(err);
          }
        }, this.requestStatusCheckInterval)
      );
    });
  }

  async cancelRequestStatusCheck(): Promise<void> {
    clearInterval(this.requestStatusCheckId);
  }

  async deleteShareTransferStore(encPubKey: string): Promise<void> {
    const currentShareTransferStore = await this.getShareTransferStore();
    delete currentShareTransferStore[encPubKey];
    await this.setShareTransferStore(currentShareTransferStore);
  }

  async resetShareTransferStore(): Promise<void> {
    const metadata = this.tbSDK.getMetadata();
    const shareTransferStorePointer = { pointer: bytesToNumberBE(generatePrivate()) };
    metadata.setGeneralStoreDomain(this.moduleName, shareTransferStorePointer);
    await this.tbSDK._syncShareMetadata();
  }

  private _cleanUpCurrentRequest(): void {
    this.currentEncKey = undefined;
    clearInterval(this.requestStatusCheckId);
  }
}

export default ShareTransferModule;
