# tKey Seed Phrase Module

[![npm version](https://img.shields.io/npm/v/@tkey/seed-phrase?label=%22%22)](https://www.npmjs.com/package/@tkey/seed-phrase/v/latest) [![minzip](https://img.shields.io/bundlephobia/minzip/@tkey/seed-phrase?label=%22%22)](https://bundlephobia.com/result?p=@tkey/seed-phrase@latest)

The tKey Seed Phrase Module helps you add or remove the and password as a share for tkey. This module is the part of the [tKey SDK](https://github.com/tkey/tkey/).

## Installation

```shell
npm install --save @tkey/seed-phrase
```

## Initialization

#### Import the `SeedPhraseModule` class from `@tkey/seed-phrase`

```javascript
import SeedPhraseModule from "@tkey/seed-phrase";
```

#### Assign the `SeedPhraseModule` class to a variable

```javascript
const seedPhraseModule = new SeedPhraseModule();
```

### Returns

The `SeedPhraseModule` class returns an object with the following properties:

```ts
declare class SeedPhraseModule implements IModule {
  moduleName: string;
  tbSDK: ITKeyApi;
  seedPhraseFormats: ISeedPhraseFormat[];
  constructor(formats: ISeedPhraseFormat[]);
  setModuleReferences(tbSDK: ITKeyApi): void;
  initialize(): Promise<void>;
  setSeedPhrase(seedPhraseType: string, seedPhrase?: string): Promise<void>;
  setSeedPhraseStoreItem(partialStore: ISeedPhraseStore): Promise<void>;
  CRITICAL_changeSeedPhrase(oldSeedPhrase: string, newSeedPhrase: string): Promise<void>;
  getSeedPhrases(): Promise<ISeedPhraseStore[]>;
  getSeedPhrasesWithAccounts(): Promise<ISeedPhraseStoreWithKeys[]>;
  getAccounts(): Promise<BN[]>;
}
```

## Usage

With the `SeedPhraseModule`, you've access to the following functions:

### Set Seed Phrase

#### `setSeedPhrase(seedPhraseType: string, seedPhrase?: string)`

- `seedPhraseType`: The type of seed phrase to set.
- `seedPhrase`: The seed phrase to set.

### Set Seed Phrase Store Item

#### `setSeedPhraseStoreItem(partialStore: ISeedPhraseStore)`

- `partialStore`: The partial store to set.

### Get Seed Phrase

#### `getSeedPhrases()`

#### Return

- `Promise<ISeedPhraseStore[]>`: A list of seed phrases.

### Get Seed Phrase With Accounts

#### `getSeedPhrasesWithAccounts()`

#### Return

- `Promise<ISeedPhraseStoreWithKeys[]>`: A list of seed phrases with accounts.
