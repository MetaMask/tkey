import { IModule, ISeedPhraseFormat, ISeedPhraseStore, ISeedPhraseStoreWithKeys, ITKeyApi } from "@tkey/common-types";

import SeedPhraseError from "./errors";

export const SEED_PHRASE_MODULE_NAME = "seedPhraseModule";

class SeedPhraseModule implements IModule {
  moduleName: string;

  tbSDK: ITKeyApi;

  seedPhraseFormats: ISeedPhraseFormat[];

  constructor(formats: ISeedPhraseFormat[]) {
    this.moduleName = SEED_PHRASE_MODULE_NAME;
    this.seedPhraseFormats = formats;
  }

  setModuleReferences(tbSDK: ITKeyApi): void {
    this.tbSDK = tbSDK;
    this.tbSDK._addReconstructKeyMiddleware(this.moduleName, this.getAccounts.bind(this));
  }

  async initialize(): Promise<void> {}

  async setSeedPhrase(seedPhraseType: string, seedPhrase?: string): Promise<void> {
    const format = this.seedPhraseFormats.find((el) => el.type === seedPhraseType);
    if (!format) {
      throw SeedPhraseError.notSupported();
    }
    if (seedPhrase && !format.validateSeedPhrase(seedPhrase)) {
      throw SeedPhraseError.invalid(`${seedPhraseType}`);
    }
    const seedPhraseStore = await format.createSeedPhraseStore(seedPhrase);
    return this.tbSDK._setTKeyStoreItem(this.moduleName, seedPhraseStore);
  }

  async setSeedPhraseStoreItem(partialStore: ISeedPhraseStore): Promise<void> {
    const seedPhraseItem = (await this.tbSDK.getTKeyStoreItem(this.moduleName, partialStore.id)) as ISeedPhraseStore;
    const originalItem: ISeedPhraseStore = { id: seedPhraseItem.id, type: seedPhraseItem.type, seedPhrase: seedPhraseItem.seedPhrase };
    // Disallow editing critical fields
    const finalItem = { ...partialStore, ...originalItem };
    return this.tbSDK._setTKeyStoreItem(this.moduleName, finalItem);
  }

  async CRITICAL_changeSeedPhrase(oldSeedPhrase: string, newSeedPhrase: string): Promise<void> {
    const seedPhrases = await this.getSeedPhrases();
    const itemToChange = seedPhrases.find((x) => x.seedPhrase === oldSeedPhrase);
    itemToChange.seedPhrase = newSeedPhrase;
    return this.tbSDK._setTKeyStoreItem(this.moduleName, itemToChange);
  }

  async getSeedPhrases(): Promise<ISeedPhraseStore[]> {
    return this.tbSDK.getTKeyStore(this.moduleName) as Promise<ISeedPhraseStore[]>;
  }

  async getSeedPhrasesWithAccounts(): Promise<ISeedPhraseStoreWithKeys[]> {
    try {
      const seedPhrases = await this.getSeedPhrases();
      return await Promise.all(
        seedPhrases.map(async (x) => {
          const suitableFormat = this.seedPhraseFormats.find((y) => y.type === x.type);
          const keys = await suitableFormat.deriveKeysFromSeedPhrase(x);
          return { ...x, keys };
        })
      );
    } catch {
      return [];
    }
  }

  async getAccounts(): Promise<bigint[]> {
    try {
      const seedPhrases = await this.getSeedPhrases();
      const responses = await Promise.all(
        seedPhrases.map(async (x) => {
          const suitableFormat = this.seedPhraseFormats.find((y) => y.type === x.type);
          return suitableFormat.deriveKeysFromSeedPhrase(x);
        })
      );
      return responses.flatMap((x) => x);
    } catch {
      return [];
    }
  }
}

export default SeedPhraseModule;
