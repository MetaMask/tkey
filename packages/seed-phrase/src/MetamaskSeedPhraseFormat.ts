import { generateID, ISeedPhraseFormat, ISeedPhraseStore, MetamaskSeedPhraseStore } from "@tkey/common-types";
import { HDNodeWallet, Mnemonic, Provider, randomBytes } from "ethers";

class MetamaskSeedPhraseFormat implements ISeedPhraseFormat {
  type: string;

  provider: Provider;

  hdPathString: string;

  constructor(ethProvider: Provider) {
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
    return Mnemonic.isValidMnemonic(parsedSeedPhrase);
  }

  async deriveKeysFromSeedPhrase(seedPhraseStore: ISeedPhraseStore): Promise<bigint[]> {
    const mmStore = seedPhraseStore as MetamaskSeedPhraseStore;
    const { seedPhrase } = mmStore;
    const hdkey = HDNodeWallet.fromSeed(Mnemonic.fromPhrase(seedPhrase).computeSeed());
    const numOfWallets = mmStore.numberOfWallets;
    const wallets: bigint[] = [];
    const root = hdkey.derivePath(this.hdPathString);
    for (let i = 0; i < numOfWallets; i += 1) {
      const child = root.deriveChild(i);
      const wallet = BigInt(child.privateKey);
      wallets.push(wallet);
    }
    return wallets;
  }

  async createSeedPhraseStore(seedPhrase?: string): Promise<MetamaskSeedPhraseStore> {
    let numberOfWallets = 0;
    let lastBalance: bigint;
    const mnemonic = seedPhrase ? Mnemonic.fromPhrase(seedPhrase) : Mnemonic.fromEntropy(randomBytes(32));
    const hdkey = HDNodeWallet.fromSeed(mnemonic.computeSeed());
    const root = hdkey.derivePath(this.hdPathString);
    // seek out the first zero balance
    while (lastBalance !== BigInt(0)) {
      const wallet = root.deriveChild(numberOfWallets);
      lastBalance = await this.provider.getBalance(wallet.address);
      numberOfWallets += 1;
    }

    const obj = {
      id: generateID(),
      type: this.type,
      seedPhrase: mnemonic.phrase,
      numberOfWallets,
    };
    return obj;
  }
}
export default MetamaskSeedPhraseFormat;
