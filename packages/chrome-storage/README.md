# tKey Chrome Storage Module

[![npm version](https://img.shields.io/npm/v/@tkey/chrome-storage?label=%22%22)](https://www.npmjs.com/package/@tkey/chrome-storage/v/latest) [![minzip](https://img.shields.io/bundlephobia/minzip/@tkey/chrome-storage?label=%22%22)](https://bundlephobia.com/result?p=@tkey/chrome-storage@latest)

The tKey Chrome Storage Module helps you store and recall key shares in the chrome extension storage. This module is the part of the [tKey SDK](https://github.com/tkey/tkey/).

## Installation

```shell
npm install --save @tkey/chrome-storage
```

## Initialization

#### Import the `ChromeExtensionStorageModule` class from `@tkey/chrome-storage`

```javascript
import ChromeExtensionStorageModule from "@tkey/chrome-storage";
```

#### Assign the `ChromeExtensionStorageModule` class to a variable

```javascript
const chromeStorageModule = new ChromeExtensionStorageModule();
```

### Returns

The `ChromeExtensionStorageModule` class returns an object with the following properties:

```ts
class ChromeExtensionStorageModule implements IModule {
  moduleName: string;
  tbSDK: ITKeyApi;
  constructor();
  setModuleReferences(tbSDK: ITKeyApi): void;
  initialize(): Promise<void>;
  storeDeviceShare(deviceShareStore: ShareStore, customDeviceInfo?: StringifiedType): Promise<void>;
  storeShareOnChromeExtensionStorage(share: ShareStore): Promise<void>;
  getStoreFromChromeExtensionStorage(): Promise<ShareStore>;
  inputShareFromChromeExtensionStorage(): Promise<void>;
}
```

## Usage

With the `ChromeExtensionStorageModule` , you've access to the following functions:

### Storing a Device Share

#### `storeDeviceShare(deviceShareStore, customDeviceInfo?)`

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

### Storing a Share on Chrome Extension Storage

#### `storeShareOnChromeExtensionStorage(share)`

- `share`: The [`ShareStore`](#sharestore) object to store.

### Get a ShareStore from Chrome Extension Storage

##### `getStoreFromChromeExtensionStorage()`

#### Return

- `Promise<ShareStore>`: The [`ShareStore`](#sharestore) object.
