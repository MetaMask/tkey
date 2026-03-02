# tKey Web Storage Module

[![npm version](https://img.shields.io/npm/v/@tkey/web-storage?label=%22%22)](https://www.npmjs.com/package/@tkey/web-storage/v/latest)                       [![minzip](https://img.shields.io/bundlephobia/minzip/@tkey/web-storage?label=%22%22)](https://bundlephobia.com/result?p=@tkey/web-storage@latest)

The tKey Web Storage Module helps you store and recall key shares in the from local and file storage. This module is the part of the [tKey SDK](https://github.com/tkey/tkey/).

## Installation

```shell
npm install --save @tkey/web-storage
```

## Initialization

#### Import the `WebStorageModule` class from `@tkey/web-storage`

```javascript
import WebStorageModule from "@tkey/web-storage";
```

#### Assign the `WebStorageModule` class to a variable

```javascript
const webStorageModule = new WebStorageModule(params);
```

### Parameters

`params`

- `canUseFileStorage?`: `boolean`

### Returns

The `WebStorageModule` class returns an object with the following properties:

```ts
class WebStorageModule implements IModule {
  moduleName: string;
  tbSDK: ITKeyApi;
  canUseFileStorage: boolean;
  constructor(canUseFileStorage?: boolean);
  setFileStorageAccess(): Promise<void>;
  setModuleReferences(tbSDK: ITKeyApi): void;
  initialize(): Promise<void>;
  storeDeviceShare(deviceShareStore: ShareStore, customDeviceInfo?: StringifiedType): Promise<void>;
  storeDeviceShareOnFileStorage(shareIndex: BigIntString): Promise<void>;
  getDeviceShare(): Promise<ShareStore>;
  inputShareFromWebStorage(): Promise<void>;
}
```

## Usage

With the `WebStorageModule`, you've access to the following functions:

### Store Device Share

#### `storeDeviceShare(deviceShareStore: ShareStore, customDeviceInfo?: StringifiedType)`

- `deviceShareStore`: The `ShareStore` object to store.
- `customDeviceInfo?`: Information about the device to store.

#### `ShareStore`

```ts
class ShareStore implements ISerializable {
  share: Share;
  polynomialID: PolynomialID;
  constructor(share: Share, polynomialID: PolynomialID);
  static fromJSON(value: StringifiedType): ShareStore;
  toJSON(): StringifiedType;
}
interface ISerializable {
  toJSON(): StringifiedType;
}
```

### Storing a Share on File Storage

#### `storeDeviceShareOnFileStorage(shareIndex)`

- `shareIndex`: The index of the share to store.

### Get a ShareStore from Storage

#### `getDeviceShare()`

#### Return

- `Promise<ShareStore>`: The [`ShareStore`](#sharestore) object.