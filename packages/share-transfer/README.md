# tKey Share Transfer Module

[![npm version](https://img.shields.io/npm/v/@tkey/share-transfer?label=%22%22)](https://www.npmjs.com/package/@tkey/share-transfer/v/latest) [![minzip](https://img.shields.io/bundlephobia/minzip/@tkey/share-transfer?label=%22%22)](https://bundlephobia.com/result?p=@tkey/share-transfer@latest)

The Share Transfer Module helps you add or remove the and password as a share for tkey. This module is the part of the [tKey SDK](https://github.com/tkey/tkey/).

## Installation

```shell
npm install --save @tkey/share-transfer
```

## Initialization

#### Import the `ShareTransferModule` class from `@tkey/share-transfer`

```javascript
import ShareTransferModule from "@tkey/share-transfer";
```

#### Assign the `ShareTransferModule` class to a variable

```javascript
const shareTransferModule = new ShareTransferModule();
```

### Returns

The `ShareTransferModule` class returns an object with the following properties:

```ts
declare class ShareTransferModule implements IModule {
  moduleName: string;
  tbSDK: ITKeyApi;
  currentEncKey: BN;
  requestStatusCheckId: number;
  requestStatusCheckInterval: number;
  constructor();
  static refreshShareTransferMiddleware(
    generalStore: unknown,
    oldShareStores: ShareStoreMap,
    newShareStores: ShareStoreMap
  ): ShareTransferStorePointer;
  setModuleReferences(tbSDK: ITKeyApi): void;
  setRequestStatusCheckInterval(interval: number): void;
  initialize(): Promise<void>;
  requestNewShare(
    userAgent: string,
    availableShareIndexes: Array<string>,
    callback?: (err?: ITkeyError, shareStore?: ShareStore) => void
  ): Promise<string>;
  addCustomInfoToShareRequest(encPubKeyX: string, customInfo: string): Promise<void>;
  lookForRequests(): Promise<Array<string>>;
  approveRequest(encPubKeyX: string, shareStore?: ShareStore): Promise<void>;
  approveRequestWithShareIndex(encPubKeyX: string, shareIndex: string): Promise<void>;
  getShareTransferStore(): Promise<ShareTransferStore>;
  setShareTransferStore(shareTransferStore: ShareTransferStore): Promise<void>;
  startRequestStatusCheck(encPubKeyX: string, deleteRequestAfterCompletion: boolean): Promise<ShareStore>;
  cancelRequestStatusCheck(): Promise<void>;
  deleteShareTransferStore(encPubKey: string): Promise<void>;
  resetShareTransferStore(): Promise<void>;
  private _cleanUpCurrentRequest;
}
```

## Usage

With the `ShareTransferModule`, you've access to the following functions:

### Request a new share

#### `requestNewShare(userAgent: string, availableShareIndexes: Array<string>, callback?: (err?: ITkeyError, shareStore?: ShareStore) => void)`

- `userAgent`: The user agent of the client that is requesting a new share.
- `availableShareIndexes`: An array of share indexes that are available for the client.
- `callback`: A callback function that is called when the request is complete.

#### Return

- `Promise<string>`: Share index of the new share.

### Add custom info to share request

#### `addCustomInfoToShareRequest(encPubKeyX: string, customInfo: string)`

- `encPubKeyX`: The public key of the share that is being requested.
- `customInfo`: The custom info that is being added to the share request.

### Look for requests

#### `lookForRequests()`

#### Return

- `Promise<Array<string>>`: An array of indexes of pending requests

### Approve request

#### `approveRequest(encPubKeyX: string, shareStore?: ShareStore)`

- `encPubKeyX`: The public key of the share that is being approved.
- `shareStore`: The share store that is being approved.

### Approve request with share index

#### `approveRequestWithShareIndex(encPubKeyX: string, shareIndex: string)`

- `encPubKeyX`: The public key of the share that is being approved.
- `shareIndex`: The share index that is being approved.

### Get share transfer store

#### `getShareTransferStore()`

#### Return

- `Promise<ShareTransferStore>`: The share transfer store.

### Set share transfer store

#### `setShareTransferStore(shareTransferStore: ShareTransferStore)`

- `shareTransferStore`: The share transfer store.

### Start request status check

#### `startRequestStatusCheck(encPubKeyX: string, deleteRequestAfterCompletion: boolean)`

- `encPubKeyX`: The public key of the share that is being checked.
- `deleteRequestAfterCompletion`: Whether or not to delete the request after it is completed.

#### Return

- `Promise<ShareStore>`: The share store.

### Cancel request status check

#### `cancelRequestStatusCheck()`

### Delete share transfer store

#### `deleteShareTransferStore(encPubKey: string)`

- `encPubKey`: The public key of the share that is being deleted.

### Reset share transfer store

#### `resetShareTransferStore()`
