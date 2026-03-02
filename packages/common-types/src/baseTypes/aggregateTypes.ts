import type { CustomAuthArgs } from "@toruslabs/customauth";

import {
  Point,
  Polynomial,
  PublicPolynomial,
  PublicPolynomialMap,
  PublicShare,
  PublicSharePolyIDShareIndexMap,
  Share,
  ShareMap,
  ShareStore,
  ShareStoreMap,
  ShareStorePolyIDShareIndexMap,
} from "../base";
import {
  BigIntString,
  EncryptedMessage,
  ISerializable,
  IServiceProvider,
  IStorageLayer,
  PolyIDAndShares,
  PolynomialID,
  ShareDescriptionMap,
} from "./commonTypes";

export interface IModule {
  moduleName: string;

  setModuleReferences(api: ITKeyApi): void;
  // called to initialize a module on the main TBSDK.
  // currenty called immediately after the base metadata has been set on the SDK
  initialize(): Promise<void>;
}

// @flow

export type ModuleMap = {
  [moduleName: string]: IModule;
};

export type RefreshMiddlewareMap = {
  [moduleName: string]: (generalStore: unknown, oldShareStores: ShareStoreMap, newShareStores: ShareStoreMap) => unknown;
};

export type ReconstructKeyMiddlewareMap = {
  [moduleName: string]: () => Promise<bigint[]>;
};

export type ShareSerializationMiddleware = {
  serialize: (share: bigint, type: string) => Promise<unknown>;
  deserialize: (serializedShare: unknown, type: string) => Promise<bigint>;
};

export type FactorEncType = "direct" | "hierarchical";

export type FactorEnc = {
  tssIndex: number;
  type: FactorEncType;
  userEnc: EncryptedMessage;
  serverEncs: EncryptedMessage[];
};

export interface IMetadata extends ISerializable {
  pubKey: Point;

  publicPolynomials: PublicPolynomialMap;

  publicShares: PublicSharePolyIDShareIndexMap;

  polyIDList: PolyIDAndShares[];

  generalStore: {
    [moduleName: string]: unknown;
  };

  tkeyStore: {
    [moduleName: string]: unknown;
  };

  scopedStore: {
    [moduleName: string]: unknown;
  };

  nonce: number;

  getShareIndexesForPolynomial(polyID: PolynomialID): string[];
  getLatestPublicPolynomial(): PublicPolynomial;
  addPublicShare(polynomialID: PolynomialID, publicShare: PublicShare): void;
  setGeneralStoreDomain(key: string, obj: unknown): void;
  getGeneralStoreDomain(key: string): unknown;
  deleteGeneralStoreDomain(key: string): unknown;
  setTkeyStoreDomain(key: string, arr: unknown): void;
  getTkeyStoreDomain(key: string): unknown;
  addFromPolynomialAndShares(polynomial: Polynomial, shares: Array<Share> | ShareMap): void;
  setScopedStore(domain: string, data: unknown): void;
  getEncryptedShare(shareStore: ShareStore): Promise<ShareStore>;
  getShareDescription(): ShareDescriptionMap;
  shareToShareStore(share: bigint): ShareStore;
  addShareDescription(shareIndex: string, description: string): void;
  deleteShareDescription(shareIndex: string, description: string): void;
  updateShareDescription(shareIndex: string, oldDescription: string, newDescription: string): void;
  clone(): IMetadata;
  updateTSSData(tssData: {
    tssTag: string;
    tssKeyType?: string;
    tssNonce?: number;
    tssPolyCommits?: Point[];
    factorPubs?: Point[];
    factorEncs?: {
      [factorPubID: string]: FactorEnc;
    };
  }): void;
}

export type InitializeNewKeyResult = {
  secp256k1Key: bigint;
  ed25519Seed?: Uint8Array;
  deviceShare?: ShareStore;
  userShare?: ShareStore;
};

export type ReconstructedKeyResult = {
  secp256k1Key: bigint;
  ed25519Seed?: Uint8Array;
  seedPhrase?: bigint[];
  allKeys?: bigint[];
};
export type MiddlewareExtraKeys = Omit<ReconstructedKeyResult, "secp256k1Key" | "ed25519Seed">;

export type CatchupToLatestShareResult = {
  latestShare: ShareStore;
  shareMetadata: IMetadata;
};

export type GenerateNewShareResult = {
  newShareStores: ShareStoreMap;
  newShareIndex: bigint;
};

export type DeleteShareResult = {
  newShareStores: ShareStoreMap;
};

export type RefreshSharesResult = {
  shareStores: ShareStoreMap;
};

export type KeyDetails = {
  pubKey: Point;
  ed25519PublicKey?: string;
  requiredShares: number;
  threshold: number;
  totalShares: number;
  shareDescriptions: ShareDescriptionMap;
};

export type TKeyArgs = {
  enableLogging?: boolean;
  modules?: ModuleMap;
  serviceProvider?: IServiceProvider;
  storageLayer?: IStorageLayer;
  customAuthArgs?: CustomAuthArgs;
  manualSync?: boolean;
  serverTimeOffset?: number;
};

export interface SecurityQuestionStoreArgs {
  nonce: BigIntString;

  shareIndex: BigIntString;

  sqPublicShare: PublicShare;

  polynomialID: PolynomialID;

  questions: string;
}

export interface TkeyStoreDataArgs {
  [key: string]: unknown;
}

export interface TkeyStoreArgs {
  data: TkeyStoreDataArgs;
}

export interface ShareTransferStorePointerArgs {
  pointer: BigIntString;
}

export type BufferObj = {
  type: string;
  data: number[];
};

export interface ShareRequestArgs {
  encPubKey: unknown;
  encShareInTransit: EncryptedMessage;
  availableShareIndexes: string[];
  userAgent: string;
  userIp: string;
  timestamp: number;
}

export type TkeyStoreItemType = {
  id: string;
};

export type IAccountSaltStore = TkeyStoreItemType & {
  value: string;
};

export type ISeedPhraseStore = TkeyStoreItemType & {
  seedPhrase: string;
  type: string;
};

export type ISQAnswerStore = TkeyStoreItemType & {
  answer: string;
};

export type ISeedPhraseStoreWithKeys = ISeedPhraseStore & {
  keys: bigint[];
};

export type MetamaskSeedPhraseStore = ISeedPhraseStore & {
  numberOfWallets: number;
};

export type IPrivateKeyStore = TkeyStoreItemType & {
  privateKey: bigint;
  type: string;
};

export interface ISeedPhraseFormat {
  type: string;
  validateSeedPhrase(seedPhrase: string): boolean;
  deriveKeysFromSeedPhrase(seedPhraseStore: ISeedPhraseStore): Promise<bigint[]>;
  createSeedPhraseStore(seedPhrase?: string): Promise<ISeedPhraseStore>;
}

export interface IPrivateKeyFormat {
  privateKey: bigint;
  type: string;
  validatePrivateKey(privateKey: bigint): boolean;
  createPrivateKeyStore(privateKey: bigint): IPrivateKeyStore;
}

export interface IAuthMetadata {
  metadata: IMetadata;
  privKey?: bigint;
}

export interface IMessageMetadata {
  message: string;
  dateAdded?: number;
}

export type IAuthMetadatas = IAuthMetadata[];
export type ShareStores = ShareStore[];
export type IMessageMetadatas = IMessageMetadata[];
export type LocalTransitionShares = bigint[];
export type LocalTransitionData = (IAuthMetadata | IMessageMetadata | ShareStore)[];
export type LocalMetadataTransitions = [LocalTransitionShares, LocalTransitionData];

export interface ITKeyApi {
  getMetadata(): IMetadata;
  getStorageLayer(): IStorageLayer;
  initialize(params: { input?: ShareStore; importKey?: bigint; neverInitializeNewKey?: boolean }): Promise<KeyDetails>;
  catchupToLatestShare(params: {
    shareStore: ShareStore;
    polyID?: string;
    includeLocalMetadataTransitions?: boolean;
  }): Promise<CatchupToLatestShareResult>;
  _syncShareMetadata(adjustScopedStore?: (ss: unknown) => unknown): Promise<void>;
  inputShareStoreSafe(shareStore: ShareStore, autoUpdateMetadata?: boolean): Promise<void>;
  _setDeviceStorage(storeDeviceStorage: (deviceShareStore: ShareStore) => Promise<void>): void;
  addShareDescription(shareIndex: string, description: string, updateMetadata?: boolean): Promise<void>;
  _addRefreshMiddleware(
    moduleName: string,
    middleware: (generalStore: unknown, oldShareStores: ShareStoreMap, newShareStores: ShareStoreMap) => unknown
  ): void;
  _addReconstructKeyMiddleware(moduleName: string, middleware: () => Promise<Array<bigint>>): void;
  _addShareSerializationMiddleware(
    serialize: (share: bigint, type: string) => Promise<unknown>,
    deserialize: (serializedShare: unknown, type: string) => Promise<bigint>
  ): void;
  generateNewShare(): Promise<GenerateNewShareResult>;
  outputShareStore(shareIndex: BigIntString, polyID?: string): ShareStore;
  inputShare(share: unknown, type?: string): Promise<void>;
  outputShare(shareIndex: BigIntString, type?: string): Promise<unknown>;
  inputShareStore(shareStore: ShareStore): void;
  deleteShare(shareIndex: BigIntString): Promise<DeleteShareResult>;
  encrypt(data: Uint8Array): Promise<EncryptedMessage>;
  decrypt(encryptedMesage: EncryptedMessage): Promise<Uint8Array>;

  getTKeyStoreItem(moduleName: string, id: string): Promise<TkeyStoreItemType>;
  getTKeyStore(moduleName: string): Promise<TkeyStoreItemType[]>;
  _deleteTKeyStoreItem(moduleName: string, id: string): Promise<void>;
  _setTKeyStoreItem(moduleName: string, data: TkeyStoreItemType, updateMetadata?: boolean): Promise<void>;
}

export interface ITKey extends ITKeyApi, ISerializable {
  modules: ModuleMap;

  enableLogging: boolean;

  serviceProvider: IServiceProvider;

  shares: ShareStorePolyIDShareIndexMap;

  secp256k1Key: bigint;

  ed25519Key: Uint8Array;

  manualSync: boolean;

  _localMetadataTransitions: LocalMetadataTransitions;

  _refreshMiddleware: RefreshMiddlewareMap;

  _reconstructKeyMiddleware: ReconstructKeyMiddlewareMap;

  _shareSerializationMiddleware: ShareSerializationMiddleware;

  initialize(params: { input?: ShareStore; importKey?: bigint; neverInitializeNewKey?: boolean }): Promise<KeyDetails>;

  reconstructKey(): Promise<ReconstructedKeyResult>;

  reconstructLatestPoly(): Polynomial;

  getKeyDetails(): KeyDetails;
}

export type TKeyInitArgs = {
  withShare?: ShareStore;
  importKey?: bigint;
  importEd25519Seed?: Uint8Array;
  neverInitializeNewKey?: boolean;
  transitionMetadata?: IMetadata;
  previouslyFetchedCloudMetadata?: IMetadata;
  previousLocalMetadataTransitions?: LocalMetadataTransitions;
  delete1OutOf1?: boolean;
};
