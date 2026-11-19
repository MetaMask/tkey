# tKey Private Key Module

[![npm version](https://img.shields.io/npm/v/@tkey/private-keys?label=%22%22)](https://www.npmjs.com/package/@tkey/private-keys/v/latest) [![minzip](https://img.shields.io/bundlephobia/minzip/@tkey/private-keys?label=%22%22)](https://bundlephobia.com/result?p=@tkey/private-keys@latest)

The tKey Private Key Module helps you add or remove the and password as a share for tkey. This module is the part of the [tKey SDK](https://github.com/tkey/tkey/).

## Installation

```shell
npm install --save @tkey/private-keys
```

## Initialization

#### Import the `PrivateKeyModule` class from `@tkey/private-keys`

```javascript
import PrivateKeyModule from "@tkey/private-keys";
```

#### Assign the `PrivateKeyModule` class to a variable

```javascript
const privateKeyModule = new PrivateKeyModule();
```

### Returns

The `PrivateKeyModule` class returns an object with the following properties:

```ts
declare class PrivateKeyModule implements IModule {
  moduleName: string;
  tbSDK: ITKeyApi;
  privateKeyFormats: IPrivateKeyFormat[];
  constructor(formats: IPrivateKeyFormat[]);
  setModuleReferences(tbSDK: ITKeyApi): void;
  initialize(): Promise<void>;
  setPrivateKey(privateKeyType: string, privateKey?: BN): Promise<void>;
  getPrivateKeys(): Promise<IPrivateKeyStore[]>;
  getAccounts(): Promise<BN[]>;
}
```

## Usage

With the `PrivateKeyModule`, you've access to the following functions:

### Set Private Key

#### `setPrivateKey(privateKeyType: string, privateKey?: BN)`

- `privateKeyType`: The type of private key to set.
- `privateKey`: The private key to set.

### Get Private Keys

#### `getPrivateKeys()`

#### Return

- `Promise<IPrivateKeyStore[]>`- The private keys stored.
