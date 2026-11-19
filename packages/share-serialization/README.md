# tKey Share Serialization Module

[![npm version](https://img.shields.io/npm/v/@tkey/share-serialization?label=%22%22)](https://www.npmjs.com/package/@tkey/share-serialization/v/latest) [![minzip](https://img.shields.io/bundlephobia/minzip/@tkey/share-serialization?label=%22%22)](https://bundlephobia.com/result?p=@tkey/share-serialization@latest)

The Share Serialization Module helps you add or remove the and password as a share for tkey. This module is the part of the [tKey SDK](https://github.com/tkey/tkey/).

## Installation

```shell
npm install --save @tkey/share-serialization
```

## Initialization

#### Import the `ShareSerializationModule` class from `@tkey/share-serialization`

```javascript
import ShareSerializationModule from "@tkey/share-serialization";
```

#### Assign the `ShareSerializationModule` class to a variable

```javascript
const shareSerializationModule = new ShareSerializationModule();
```

### Returns

The `ShareSerializationModule` class returns an object with the following properties:

```ts
declare class ShareSerializationModule implements IModule {
  moduleName: string;
  tbSDK: ITKeyApi;
  constructor();
  static serializeMnemonic(share: BN): string;
  static deserializeMnemonic(share: string): BN;
  setModuleReferences(tbSDK: ITKeyApi): void;
  initialize(): Promise<void>;
  serialize(share: BN, type: string): Promise<unknown>;
  deserialize(serializedShare: unknown, type: string): Promise<BN>;
}
```

## Usage

With the `ShareSerializationModule`, you've access to the following functions:

### Serialize a share

#### `serialize(share: BN, type: string)`

- `share`: The share to serialize.
- `type`: The type of share to serialize.

### Deserialize a share

#### `deserialize(serializedShare: unknown, type: string)`

#### Return

- `Promise<BN>`: The deserialized share.
