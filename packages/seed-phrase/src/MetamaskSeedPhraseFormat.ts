import { HDKey } from "@scure/bip32";
import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import {
  generateAddressFromPublicKey,
  generateID,
  generatePrivate,
  getPubKeyECC,
  ISeedPhraseFormat,
  ISeedPhraseStore,
  MetamaskSeedPhraseStore,
} from "@tkey/common-types";
import { bytesToBigInt } from "@toruslabs/metadata-helpers";

export interface EthProvider {
  getBalance(address: string): Promise<bigint>;
}

class MetamaskSeedPhraseFormat implements ISeedPhraseFormat {
  type: string;

  provider: EthProvider;

  hdPathString: string;

  constructor(ethProvider: EthProvider) {
    this.type = "HD Key Tree";
    this.hdPathString = "m/44'/60'/0'/0";
    this.provider = ethProvider;
  }

  validateSeedPhrase(seedPhrase: string): boolean {
    const parsedSeedPhrase = (seedPhrase || "").trim().toLowerCase().match(/\w+/gu)?.join(" ") || "";
    const wordCount = parsedSeedPhrase.split(/\s/u).length;
    if (wordCount % 3 !== 0 || wordCount > 24 || wordCount < 12) {
      return false;
    }
    return validateMnemonic(parsedSeedPhrase, wordlist);
  }

  async deriveKeysFromSeedPhrase(seedPhraseStore: ISeedPhraseStore): Promise<bigint[]> {
    const mmStore = seedPhraseStore as MetamaskSeedPhraseStore;
    const { seedPhrase } = mmStore;
    const seed = mnemonicToSeedSync(seedPhrase);
    const hdkey = HDKey.fromMasterSeed(seed);
    const numOfWallets = mmStore.numberOfWallets;
    const wallets: bigint[] = [];
    const root = hdkey.derive(this.hdPathString);
    for (let i = 0; i < numOfWallets; i += 1) {
      const child = root.deriveChild(i);
      const wallet = bytesToBigInt(child.privateKey);
      wallets.push(wallet);
    }
    return wallets;
  }

  async createSeedPhraseStore(seedPhrase?: string): Promise<MetamaskSeedPhraseStore> {
    let numberOfWallets = 0;
    let lastBalance: bigint;
    let phrase: string;
    if (seedPhrase) {
      phrase = seedPhrase;
    } else {
      phrase = entropyToMnemonic(generatePrivate(), wordlist);
    }
    const seed = mnemonicToSeedSync(phrase);
    const hdkey = HDKey.fromMasterSeed(seed);
    const root = hdkey.derive(this.hdPathString);
    // seek out the first zero balance
    while (lastBalance !== BigInt(0)) {
      const child = root.deriveChild(numberOfWallets);
      const privKeyBigInt = bytesToBigInt(child.privateKey);
      const uncompressedPubKey = getPubKeyECC(privKeyBigInt).slice(1);
      const address = generateAddressFromPublicKey(uncompressedPubKey);
      lastBalance = await this.provider.getBalance(address);
      numberOfWallets += 1;
    }

    const obj = {
      id: generateID(),
      type: this.type,
      seedPhrase: phrase,
      numberOfWallets,
    };
    return obj;
  }
}
export default MetamaskSeedPhraseFormat;
