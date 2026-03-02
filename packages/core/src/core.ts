import { randomBytes } from "@noble/curves/utils.js";
import {
  bigIntReplacer,
  BigIntString,
  CatchupToLatestShareResult,
  decrypt,
  DeleteShareResult,
  encrypt,
  EncryptedMessage,
  FromJSONConstructor,
  GenerateNewShareResult,
  generatePrivateExcludingIndexes,
  getPubKeyECC,
  getPubKeyPoint,
  IMessageMetadata,
  IMetadata,
  InitializeNewKeyResult,
  IServiceProvider,
  IStorageLayer,
  ITKey,
  ITKeyApi,
  KEY_NOT_FOUND,
  KeyDetails,
  LocalMetadataTransitions,
  LocalTransitionData,
  LocalTransitionShares,
  MiddlewareExtraKeys,
  ModuleMap,
  ONE_KEY_DELETE_NONCE,
  Point,
  Polynomial,
  PolynomialID,
  prettyPrintError,
  ReconstructedKeyResult,
  ReconstructKeyMiddlewareMap,
  RefreshMiddlewareMap,
  RefreshSharesResult,
  Share,
  SHARE_DELETED,
  ShareSerializationMiddleware,
  ShareStore,
  ShareStoreMap,
  ShareStorePolyIDShareIndexMap,
  StringifiedType,
  TKeyArgs,
  TKeyInitArgs,
  TkeyStoreItemType,
  toPrivKeyECC,
} from "@tkey/common-types";
import { bytesToHex, bytesToUtf8, hexToBytes, utf8ToBytes } from "@toruslabs/metadata-helpers";
import { encodeEd25519Point, getEd25519ExtendedPublicKey as getEd25519KeyPairFromSeed } from "@toruslabs/torus.js";
import stringify from "json-stable-stringify";

import AuthMetadata from "./authMetadata";
import CoreError from "./errors";
import {
  generatePrivateBigInt,
  generateRandomPolynomial,
  lagrangeInterpolatePolynomial,
  lagrangeInterpolation,
} from "./lagrangeInterpolatePolynomial";
import Metadata from "./metadata";

const ed25519SeedConst = "ed25519Seed";

function hexToBigInt(s: string): bigint {
  return BigInt(`0x${s}`);
}

// TODO: handle errors for get and set with retries

class ThresholdKey implements ITKey {
  modules: ModuleMap;

  enableLogging: boolean;

  serviceProvider: IServiceProvider;

  storageLayer: IStorageLayer;

  shares: ShareStorePolyIDShareIndexMap;

  lastFetchedCloudMetadata: Metadata;

  metadata: Metadata;

  manualSync: boolean;

  _localMetadataTransitions: LocalMetadataTransitions;

  _refreshMiddleware: RefreshMiddlewareMap;

  _reconstructKeyMiddleware: ReconstructKeyMiddlewareMap;

  _shareSerializationMiddleware: ShareSerializationMiddleware;

  storeDeviceShare: (deviceShareStore: ShareStore, customDeviceInfo?: StringifiedType) => Promise<void>;

  haveWriteMetadataLock: string;

  serverTimeOffset?: number = 0;

  // secp256k1 key
  private privKey: bigint;

  private _ed25519Seed?: Uint8Array;

  constructor(args?: TKeyArgs) {
    const { enableLogging = false, modules = {}, serviceProvider, storageLayer, manualSync = false, serverTimeOffset } = args || {};
    this.enableLogging = enableLogging;
    this.serviceProvider = serviceProvider;
    this.storageLayer = storageLayer;
    this.modules = modules;
    this.shares = {};
    this.privKey = undefined;
    this.manualSync = manualSync;
    this._refreshMiddleware = {};
    this._reconstructKeyMiddleware = {};
    this._shareSerializationMiddleware = undefined;
    this.storeDeviceShare = undefined;
    this._localMetadataTransitions = [[], []];
    this.setModuleReferences(); // Providing ITKeyApi access to modules
    this.haveWriteMetadataLock = "";
    this.serverTimeOffset = serverTimeOffset;
  }

  get secp256k1Key(): bigint | null {
    if (typeof this.privKey !== "undefined") {
      return this.privKey;
    }

    return null;
  }

  get ed25519Key(): Uint8Array | null {
    if (typeof this._ed25519Seed !== "undefined") {
      return this._ed25519Seed;
    }
    return null;
  }

  protected set secp256k1Key(privKey: bigint) {
    this.privKey = privKey;
  }

  protected set ed25519Key(seed: Uint8Array) {
    this._ed25519Seed = seed;
  }

  static async fromJSON(value: StringifiedType, args: TKeyArgs): Promise<ThresholdKey> {
    const {
      enableLogging,
      privKey,
      ed25519Key,
      metadata,
      shares,
      _localMetadataTransitions,
      manualSync,
      lastFetchedCloudMetadata,
      serverTimeOffset,
    } = value;
    const { storageLayer, serviceProvider, modules } = args;

    const tb = new ThresholdKey({
      enableLogging,
      storageLayer,
      serviceProvider,
      modules,
      manualSync,
      serverTimeOffset,
    });

    // this will computed during reconstructKey should we restore here?
    if (privKey) tb.privKey = hexToBigInt(privKey);
    if (ed25519Key) tb.ed25519Key = hexToBytes(ed25519Key);

    const deserializedShares: ShareStorePolyIDShareIndexMap = {};
    for (const polyID of Object.keys(shares)) {
      deserializedShares[polyID] = {};
      for (const shareIndex of Object.keys(shares[polyID])) {
        deserializedShares[polyID][shareIndex] = ShareStore.fromJSON(shares[polyID][shareIndex]);
      }
    }
    tb.shares = deserializedShares;

    // switch to deserialize local metadata transition based on Object.keys() of authMetadata, ShareStore's and, IMessageMetadata
    const dummyPoint = getPubKeyPoint(1n);
    const AuthMetadataKeys = Object.keys(JSON.parse(stringify(new AuthMetadata(new Metadata(dummyPoint), 1n), { replacer: bigIntReplacer })));
    const ShareStoreKeys = Object.keys(JSON.parse(stringify(new ShareStore(new Share(1n, 1n), ""), { replacer: bigIntReplacer })));
    const sampleMessageMetadata: IMessageMetadata = { message: "Sample message", dateAdded: Date.now() };
    const MessageMetadataKeys = Object.keys(sampleMessageMetadata);

    const localTransitionShares: LocalTransitionShares = [];
    const localTransitionData: LocalTransitionData = [];

    _localMetadataTransitions[0].forEach((x: string, index: number) => {
      if (x) {
        localTransitionShares.push(hexToBigInt(x));
      } else {
        localTransitionShares.push(undefined);
      }

      const keys = Object.keys(_localMetadataTransitions[1][index]);
      if (keys.length === AuthMetadataKeys.length && keys.every((val) => AuthMetadataKeys.includes(val))) {
        const tempAuth = AuthMetadata.fromJSON(_localMetadataTransitions[1][index]);
        tempAuth.privKey = tb.privKey;
        localTransitionData.push(tempAuth);
      } else if (keys.length === ShareStoreKeys.length && keys.every((val) => ShareStoreKeys.includes(val))) {
        localTransitionData.push(ShareStore.fromJSON(_localMetadataTransitions[1][index]));
      } else if (keys.length === MessageMetadataKeys.length && keys.every((val) => MessageMetadataKeys.includes(val))) {
        localTransitionData.push(_localMetadataTransitions[1][index] as IMessageMetadata);
      } else {
        throw CoreError.default("fromJSON failed. Could not deserialise _localMetadataTransitions");
      }
    });

    if (metadata) {
      let tempMetadata: Metadata;
      let tempCloud: Metadata;

      if (metadata) tempMetadata = Metadata.fromJSON(metadata);
      if (lastFetchedCloudMetadata) tempCloud = Metadata.fromJSON(lastFetchedCloudMetadata);
      // check if cloud metadata is updated before

      tb.metadata = tempMetadata;
      tb.lastFetchedCloudMetadata = tempCloud;
      tb._localMetadataTransitions = [localTransitionShares, localTransitionData];

      if (tempCloud) {
        let shareToUseForSerialization: ShareStore;
        // if service provider key is missing, we should initialize with one of the existing shares
        // TODO: fix for deleted share
        const latestPolyIDOnCloud = tempCloud.getLatestPublicPolynomial().getPolynomialID();
        if (tb.serviceProvider.postboxKey.toString(16) === "0") {
          const shareIndexesExistInSDK = Object.keys(tb.shares[latestPolyIDOnCloud]);
          const randomIndex = shareIndexesExistInSDK[Math.floor(Math.random() * (shareIndexesExistInSDK.length - 1))];
          if (shareIndexesExistInSDK.length >= 1) {
            shareToUseForSerialization = tb.shares[latestPolyIDOnCloud][randomIndex];
          }
        } else {
          // social share index is always1
          shareToUseForSerialization = tb.shares[latestPolyIDOnCloud]["1"];
        }

        // if tempCloud exist, share must able to catchup to latest share
        // as syncmetadata is called before
        const result = await tb.catchupToLatestShare({ shareStore: shareToUseForSerialization });
        if (result) {
          // expecting nonce to be same for latest share nonce and lastfetchedcloudMetadata nonce
          if (result.shareMetadata.nonce > tb.lastFetchedCloudMetadata.nonce) {
            throw CoreError.fromCode(1104);
          } else if (result.shareMetadata.nonce < tb.lastFetchedCloudMetadata.nonce) {
            throw CoreError.fromCode(1105);
          }
        }
      }

      // initialize module as in initialize
      tb.initializeModules();
    }

    // if metadata is undefined, it mean that the tkey instance is not initialized previously
    return tb;
  }

  getStorageLayer(): IStorageLayer {
    return this.storageLayer;
  }

  getMetadata(): IMetadata {
    if (typeof this.metadata !== "undefined") {
      return this.metadata;
    }

    throw CoreError.metadataUndefined();
  }

  async initialize(params?: TKeyInitArgs): Promise<KeyDetails> {
    // setup initial params/states
    const p = params || {};

    if (p.delete1OutOf1 && !this.manualSync) throw CoreError.delete1OutOf1OnlyManualSync();

    const {
      withShare,
      importKey,
      importEd25519Seed,
      neverInitializeNewKey,
      transitionMetadata,
      previouslyFetchedCloudMetadata,
      previousLocalMetadataTransitions,
    } = p;

    const previousLocalMetadataTransitionsExists =
      previousLocalMetadataTransitions && previousLocalMetadataTransitions[0].length > 0 && previousLocalMetadataTransitions[1].length > 0;
    const reinitializing = transitionMetadata && previousLocalMetadataTransitionsExists; // are we reinitializing the SDK?
    // in the case we're reinitializing whilst newKeyAssign has not been synced
    const reinitializingWithNewKeyAssign = reinitializing && previouslyFetchedCloudMetadata === undefined;

    let shareStore: ShareStore;
    if (withShare instanceof ShareStore) {
      shareStore = withShare;
    } else if (typeof withShare === "object") {
      shareStore = ShareStore.fromJSON(withShare);
    } else if (!withShare) {
      // default to use service provider
      // first we see if a share has been kept for us
      const spIncludeLocalMetadataTransitions = reinitializingWithNewKeyAssign;
      const spLocalMetadataTransitions = reinitializingWithNewKeyAssign ? previousLocalMetadataTransitions : undefined;
      const rawServiceProviderShare = await this.getGenericMetadataWithTransitionStates({
        serviceProvider: this.serviceProvider,
        includeLocalMetadataTransitions: spIncludeLocalMetadataTransitions,
        _localMetadataTransitions: spLocalMetadataTransitions,
        fromJSONConstructor: {
          fromJSON(val: StringifiedType) {
            return val;
          },
        },
      });

      const noKeyFound: { message?: string } = rawServiceProviderShare as { message?: string };
      if (noKeyFound.message === KEY_NOT_FOUND) {
        if (neverInitializeNewKey) {
          throw CoreError.default("key has not been generated yet");
        }

        // no metadata set, assumes new user
        // check for serviceprovider migratableKey for import key from service provider for new user
        // provided no importKey is provided ( importKey take precedent )
        if (this.serviceProvider.migratableKey && !(importKey || importEd25519Seed)) {
          // importkey from server provider need to be atomic, hence manual sync is required.
          const tempStateManualSync = this.manualSync; // temp store manual sync flag
          this.manualSync = true; // Setting this as true since _initializeNewKey has a check where for importkey from server provider need to be atomic, hence manual sync is required.
          await this._initializeNewKey({ initializeModules: true, importedKey: this.serviceProvider.migratableKey, delete1OutOf1: true });
          if (!tempStateManualSync) await this.syncLocalMetadataTransitions(); // Only sync if we were not in manual sync mode, if manual sync is set by developer, they should handle it themselves
          // restore manual sync flag
          this.manualSync = tempStateManualSync;
        } else {
          await this._initializeNewKey({
            initializeModules: true,
            importedKey: importKey,
            delete1OutOf1: p.delete1OutOf1,
            importEd25519Seed,
          });
        }

        // return after created new tkey account ( skip other steps)
        return this.getKeyDetails();
      }
      // else we continue with catching up share and metadata
      shareStore = rawServiceProviderShare instanceof ShareStore ? rawServiceProviderShare : ShareStore.fromJSON(rawServiceProviderShare);
    } else {
      throw CoreError.default("Input is not supported");
    }

    // We determine the latest metadata on the SDK and if there has been
    // needed transitions to include
    let currentMetadata: Metadata;
    let latestCloudMetadata: Metadata;
    // we fetch the latest metadata for the account from the share
    let latestShareDetails: CatchupToLatestShareResult;
    try {
      latestShareDetails = await this.catchupToLatestShare({ shareStore });
    } catch (error: unknown) {
      // check if error is not the undefined error
      // if so we don't throw immediately incase there is valid transition metadata
      const err = error as Error & { code?: number };
      const noMetadataExistsForShare = err.code === 1503;
      if (!noMetadataExistsForShare || !reinitializing) {
        throw err;
      }
    }

    // lets check if the cloud metadata has been updated or not from previously if we are reinitializing
    if (reinitializing && !reinitializingWithNewKeyAssign) {
      if (previouslyFetchedCloudMetadata.nonce < latestShareDetails.shareMetadata.nonce) {
        throw CoreError.fromCode(1104);
      } else if (previouslyFetchedCloudMetadata.nonce > latestShareDetails.shareMetadata.nonce) {
        throw CoreError.fromCode(1105);
      }
      latestCloudMetadata = previouslyFetchedCloudMetadata ? previouslyFetchedCloudMetadata.clone() : undefined;
    } else {
      latestCloudMetadata = latestShareDetails ? latestShareDetails.shareMetadata.clone() : undefined;
    }

    // If we've been provided with transition metadata we use that as the current metadata instead
    // as we want to maintain state before and after serialization.
    // (Given that the checks for cloud metadata pass)
    if (reinitializing) {
      currentMetadata = transitionMetadata;
      this._localMetadataTransitions = previousLocalMetadataTransitions;
    } else {
      currentMetadata = latestShareDetails.shareMetadata;
    }

    this.lastFetchedCloudMetadata = latestCloudMetadata;
    this.metadata = currentMetadata.clone();
    const latestShare = latestShareDetails ? latestShareDetails.latestShare : shareStore;
    this.inputShareStore(latestShare);

    if (importEd25519Seed && this.getEd25519PublicKey()) {
      throw CoreError.default("Ed25119 key already exists");
    }

    // initialize modules
    await this.initializeModules();

    return this.getKeyDetails();
  }

  /**
   * catchupToLatestShare recursively loops fetches metadata of the provided share and checks if there is an encrypted share for it.
   * @param shareStore - share to start of with
   * @param polyID - if specified, polyID to refresh to if it exists
   */
  async catchupToLatestShare(params: {
    shareStore: ShareStore;
    polyID?: PolynomialID;
    includeLocalMetadataTransitions?: boolean;
  }): Promise<CatchupToLatestShareResult> {
    const { shareStore, polyID, includeLocalMetadataTransitions } = params;
    let shareMetadata: Metadata;
    try {
      shareMetadata = await this.getAuthMetadata({ privKey: shareStore.share.share, includeLocalMetadataTransitions });
    } catch (error: unknown) {
      // delete share error
      const err = error as Error & { code?: number };
      if ((err as CoreError) && err.code === 1308) {
        throw err;
      }
      const prettyError = await prettyPrintError(err);
      throw CoreError.authMetadataGetUnavailable(`, ${prettyError.message}`);
    }

    try {
      // if matches specified polyID return it
      if (polyID) {
        if (shareStore.polynomialID === polyID) {
          return { latestShare: shareStore, shareMetadata };
        }
      }
      const nextShare = await shareMetadata.getEncryptedShare(shareStore);
      return await this.catchupToLatestShare({ shareStore: nextShare, polyID, includeLocalMetadataTransitions });
    } catch (error: unknown) {
      // delete share error
      const err = error as Error & { code?: number };
      if ((err as CoreError) && err.code === 1308) {
        throw err;
      }
      return { latestShare: shareStore, shareMetadata };
    }
  }

  async reconstructKey(_reconstructKeyMiddleware = true): Promise<ReconstructedKeyResult> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    const pubPoly = this.metadata.getLatestPublicPolynomial();
    const requiredThreshold = pubPoly.getThreshold();
    const pubPolyID = pubPoly.getPolynomialID();

    // check if we have enough shares to meet threshold
    let sharesLeft = requiredThreshold;
    // we don't just check the latest poly but
    // we check if the shares on previous polynomials in our stores have the share indexes we require
    const fullShareList = this.metadata.getShareIndexesForPolynomial(pubPolyID);
    const shareIndexesRequired: Record<string, boolean> = {};
    for (let i = 0; i < fullShareList.length; i += 1) {
      shareIndexesRequired[fullShareList[i]] = true;
    }
    const sharesToInput = [];
    for (let z = this.metadata.polyIDList.length - 1; z >= 0 && sharesLeft > 0; z -= 1) {
      const sharesForPoly = this.shares[this.metadata.polyIDList[z][0]];
      if (sharesForPoly) {
        const shareIndexesForPoly = Object.keys(sharesForPoly);
        for (let k = 0; k < shareIndexesForPoly.length && sharesLeft > 0; k += 1) {
          if (shareIndexesForPoly[k] in shareIndexesRequired) {
            const currentShareForPoly = sharesForPoly[shareIndexesForPoly[k]];
            if (currentShareForPoly.polynomialID === pubPolyID) {
              sharesToInput.push(currentShareForPoly);
            } else {
              const latestShareRes = await this.catchupToLatestShare({
                shareStore: currentShareForPoly,
                polyID: pubPolyID,
                includeLocalMetadataTransitions: true,
              });
              if (latestShareRes.latestShare.polynomialID === pubPolyID) {
                sharesToInput.push(latestShareRes.latestShare);
              } else {
                throw new CoreError(1304, "Share found in unexpected polynomial"); // Share found in unexpected polynomial
              }
            }
            delete shareIndexesRequired[shareIndexesForPoly[k]];
            sharesLeft -= 1;
          }
        }
      }
    }

    // Input shares to ensure atomicity
    sharesToInput.forEach((share) => {
      this.inputShareStore(share);
    });

    if (sharesLeft > 0) {
      throw CoreError.unableToReconstruct(` require ${requiredThreshold} but have ${requiredThreshold - sharesLeft}`);
    }

    const polyShares = Object.keys(this.shares[pubPolyID]);
    const shareArr = [];
    const shareIndexArr = [];
    for (let i = 0; i < requiredThreshold; i += 1) {
      shareArr.push(this.shares[pubPolyID][polyShares[i]].share.share);
      shareIndexArr.push(this.shares[pubPolyID][polyShares[i]].share.shareIndex);
    }
    const privKey = lagrangeInterpolation(shareArr, shareIndexArr);
    // check that priv key regenerated is correct
    const reconstructedPubKey = getPubKeyPoint(privKey);
    if (this.metadata.pubKey.x !== reconstructedPubKey.x) {
      throw CoreError.incorrectReconstruction();
    }
    this.secp256k1Key = privKey;

    const returnObject: MiddlewareExtraKeys = {
      allKeys: [privKey],
    };

    if (_reconstructKeyMiddleware && Object.keys(this._reconstructKeyMiddleware).length > 0) {
      // retireve/reconstruct extra keys that live on metadata
      await Promise.all(
        Object.keys(this._reconstructKeyMiddleware).map(async (x: string) => {
          if (Object.prototype.hasOwnProperty.call(this._reconstructKeyMiddleware, x)) {
            const extraKeys = await this._reconstructKeyMiddleware[x]();
            returnObject[x as keyof MiddlewareExtraKeys] = extraKeys;
            (returnObject.allKeys as bigint[]).push(...extraKeys);
          }
        })
      );
    }

    // ed25519key
    if (this.getEd25519PublicKey()) {
      const seed = await this.retrieveEd25519Seed();
      if (!seed) {
        throw CoreError.default("Ed25519 seed not found");
      }
      this._ed25519Seed = seed;
    }
    return { secp256k1Key: privKey, ed25519Seed: this._ed25519Seed, ...returnObject };
  }

  reconstructLatestPoly(): Polynomial {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    const pubPoly = this.metadata.getLatestPublicPolynomial();
    const pubPolyID = pubPoly.getPolynomialID();
    const threshold = pubPoly.getThreshold();

    const pointsArr = [];
    const sharesForExistingPoly = Object.keys(this.shares[pubPolyID]);
    if (sharesForExistingPoly.length < threshold) {
      throw CoreError.unableToReconstruct("not enough shares to reconstruct poly");
    }
    if (new Set(sharesForExistingPoly).size !== sharesForExistingPoly.length) {
      throw CoreError.default("share indexes should be unique");
    }
    for (let i = 0; i < threshold; i += 1) {
      pointsArr.push(new Point(hexToBigInt(sharesForExistingPoly[i]), this.shares[pubPolyID][sharesForExistingPoly[i]].share.share));
    }
    return lagrangeInterpolatePolynomial(pointsArr);
  }

  async deleteShare(shareIndex: BigIntString): Promise<DeleteShareResult> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    if (!this.privKey) {
      throw CoreError.privateKeyUnavailable();
    }
    const shareIndexToDelete = typeof shareIndex === "string" ? hexToBigInt(shareIndex) : shareIndex;
    const shareToDelete = this.outputShareStore(shareIndexToDelete);
    if (shareIndexToDelete === 1n) {
      throw new CoreError(1001, "Unable to delete service provider share");
    }

    // Get existing shares
    const pubPoly = this.metadata.getLatestPublicPolynomial();
    const previousPolyID = pubPoly.getPolynomialID();
    const existingShareIndexes = this.metadata.getShareIndexesForPolynomial(previousPolyID);
    const newShareIndexes: string[] = [];
    existingShareIndexes.forEach((el) => {
      if (hexToBigInt(el) !== shareIndexToDelete) {
        newShareIndexes.push(el);
      }
    });

    // Update shares
    if (existingShareIndexes.length === newShareIndexes.length) {
      throw CoreError.default("Share index does not exist in latest polynomial");
    } else if (newShareIndexes.length < pubPoly.getThreshold()) {
      throw CoreError.default(`Minimum ${pubPoly.getThreshold()} shares are required for tkey. Unable to delete share`);
    }
    const results = await this._refreshShares(pubPoly.getThreshold(), [...newShareIndexes], previousPolyID);
    const newShareStores = results.shareStores;
    await this.addLocalMetadataTransitions({ input: [{ message: SHARE_DELETED, dateAdded: Date.now() }], privKey: [shareToDelete.share.share] });
    return { newShareStores };
  }

  async generateNewShare(): Promise<GenerateNewShareResult> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    if (!this.secp256k1Key) {
      throw CoreError.privateKeyUnavailable();
    }
    const pubPoly = this.metadata.getLatestPublicPolynomial();
    const previousPolyID = pubPoly.getPolynomialID();
    const existingShareIndexes = this.metadata.getShareIndexesForPolynomial(previousPolyID);
    const existingShareIndexesBigInt = existingShareIndexes.map((el) => hexToBigInt(el));
    const newShareIndex = generatePrivateExcludingIndexes(existingShareIndexesBigInt);

    const results = await this._refreshShares(pubPoly.getThreshold(), [...existingShareIndexes, newShareIndex.toString(16)], previousPolyID);
    const newShareStores = results.shareStores;

    return { newShareStores, newShareIndex };
  }

  getEd25519PublicKey(): string | undefined {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    const result = this.metadata.getGeneralStoreDomain(ed25519SeedConst) as { message: EncryptedMessage; publicKey: string };
    return result?.publicKey;
  }

  async retrieveEd25519Seed(): Promise<Uint8Array> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    if (!this.privKey) {
      throw CoreError.privateKeyUnavailable();
    }

    const result = this.metadata.getGeneralStoreDomain(ed25519SeedConst) as { message: EncryptedMessage; publicKey: string };
    const seed = await this.decrypt(result.message);
    this._ed25519Seed = seed;
    return seed;
  }

  async addLocalMetadataTransitions(params: {
    input: LocalTransitionData;
    serviceProvider?: IServiceProvider;
    privKey?: bigint[];
    acquireLock?: boolean;
  }): Promise<void> {
    const { privKey, input } = params;
    this._localMetadataTransitions[0] = [...this._localMetadataTransitions[0], ...privKey];
    this._localMetadataTransitions[1] = [...this._localMetadataTransitions[1], ...input];
    if (!this.manualSync) await this.syncLocalMetadataTransitions();
  }

  async syncLocalMetadataTransitions(): Promise<void> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    if (!(Array.isArray(this._localMetadataTransitions[0]) && this._localMetadataTransitions[0].length > 0)) return;

    // get lock
    let acquiredLock = false;
    if (this.lastFetchedCloudMetadata) {
      await this.acquireWriteMetadataLock();
      acquiredLock = true;
    }
    try {
      await this.storageLayer.setMetadataStream({
        input: this._localMetadataTransitions[1],
        privKey: this._localMetadataTransitions[0],
        serviceProvider: this.serviceProvider,
      });
      this._localMetadataTransitions = [[], []];
      this.lastFetchedCloudMetadata = this.metadata.clone();
    } catch (error: unknown) {
      const prettyError = await prettyPrintError(error);
      throw CoreError.metadataPostFailed(prettyError.message);
    } finally {
      // release lock
      if (acquiredLock) await this.releaseWriteMetadataLock();
    }
  }

  async readMetadata<T>(privKey: bigint): Promise<T> {
    return this.storageLayer.getMetadata<T>({ privKey });
  }

  // Returns a new instance of metadata with a clean state. All the previous state will be reset.
  async updateSDK(params?: { withShare?: ShareStore }): Promise<ThresholdKey> {
    const tb = new ThresholdKey({
      enableLogging: this.enableLogging,
      modules: this.modules,
      serviceProvider: this.serviceProvider,
      storageLayer: this.storageLayer,
      manualSync: this.manualSync,
    });

    try {
      await tb.initialize({ neverInitializeNewKey: true, withShare: params && params.withShare });
    } catch (err: unknown) {
      throw CoreError.fromCode(1103, `${(err as Error).message}`);
    }

    // Delete unnecessary polyIDs and shareStores
    const allPolyIDList = tb.metadata.polyIDList;
    let lastValidPolyID: string;

    Object.keys(this.shares).forEach((x) => {
      if (allPolyIDList.find((id) => id[0] === x)) {
        lastValidPolyID = x;
      } else {
        delete this.shares[x];
      }
    });

    // catchup to latest shareStore for all latest available shares.
    // TODO: fix edge cases where shares are deleted in the newer polynomials
    // TODO: maybe assign this.shares directly rather than output and inputsharestore.
    const shareStoresForLastValidPolyID = Object.keys(this.shares[lastValidPolyID]).map((x) =>
      tb.inputShareStoreSafe(this.outputShareStore(x, lastValidPolyID))
    );
    await Promise.all(shareStoresForLastValidPolyID);
    return tb;
  }

  // NOTE: This API will be DEPRECATED in the future in favour of inputShareStoreSafe()
  inputShareStore(shareStore: ShareStore): void {
    let ss: ShareStore;
    if (shareStore instanceof ShareStore) {
      ss = shareStore;
    } else if (typeof shareStore === "object") {
      ss = ShareStore.fromJSON(shareStore);
    } else {
      throw CoreError.default("can only add type ShareStore into shares");
    }
    if (!(ss.polynomialID in this.shares)) {
      this.shares[ss.polynomialID] = {};
    }
    this.shares[ss.polynomialID][ss.share.shareIndex.toString(16)] = ss;
  }

  // inputs a share ensuring that the share is the latest share AND metadata is updated to its latest state
  async inputShareStoreSafe(shareStore: ShareStore, autoUpdateMetadata = false): Promise<void> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    let ss: ShareStore;
    if (shareStore instanceof ShareStore) {
      ss = shareStore;
    } else if (typeof shareStore === "object") {
      ss = ShareStore.fromJSON(shareStore);
    } else {
      throw CoreError.default("can only add type ShareStore into shares");
    }
    const polynomialId = this.metadata.getLatestPublicPolynomial().getPolynomialID();
    if (ss.polynomialID !== polynomialId) {
      const latestShareRes = await this.catchupToLatestShare({ shareStore: ss, includeLocalMetadataTransitions: true });
      // check if the latest share is part of the current tkey instances
      // to avoid random share getting input into metadata
      if (!latestShareRes.shareMetadata.polyIDList.find((tuple) => tuple[0] === polynomialId)) {
        throw CoreError.fromCode(1307);
      }
      // if latest share's polynomial is not equal with tkey latest polynomial, tkey's metadata is outdated
      if (polynomialId !== latestShareRes.latestShare.polynomialID) {
        if (!autoUpdateMetadata)
          throw CoreError.default(
            `TKey SDK metadata seems to be outdated because shareIndex: ` +
              `${latestShareRes.latestShare.share.shareIndex.toString(16)} has a more recent metadata. Please call updateSDK first`
          );
        else this.metadata = latestShareRes.shareMetadata;
      }
      if (!(latestShareRes.latestShare.polynomialID in this.shares)) {
        this.shares[latestShareRes.latestShare.polynomialID] = {};
      }
      this.shares[latestShareRes.latestShare.polynomialID][latestShareRes.latestShare.share.shareIndex.toString(16)] = latestShareRes.latestShare;
    } else {
      if (!(ss.polynomialID in this.shares)) {
        this.shares[ss.polynomialID] = {};
      }
      this.shares[ss.polynomialID][ss.share.shareIndex.toString(16)] = ss;
    }
  }

  outputShareStore(shareIndex: BigIntString, polyID?: string): ShareStore {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    let shareIndexParsed: bigint;
    if (typeof shareIndex === "bigint") {
      shareIndexParsed = shareIndex;
    } else if (typeof shareIndex === "string") {
      shareIndexParsed = hexToBigInt(shareIndex);
    }
    let polyIDToSearch: string;
    if (polyID) {
      polyIDToSearch = polyID;
    } else {
      polyIDToSearch = this.metadata.getLatestPublicPolynomial().getPolynomialID();
    }
    if (!this.metadata.getShareIndexesForPolynomial(polyIDToSearch).includes(shareIndexParsed.toString(16))) {
      throw new CoreError(1002, "no such share index created");
    }
    const shareFromStore = this.shares[polyIDToSearch][shareIndexParsed.toString(16)];
    if (shareFromStore) return shareFromStore;
    const poly = this.reconstructLatestPoly();
    const shareMap = poly.generateShares([shareIndexParsed]);

    return new ShareStore(shareMap[shareIndexParsed.toString(16)], polyIDToSearch);
  }

  getCurrentShareIndexes(): string[] {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    const latestPolynomial = this.metadata.getLatestPublicPolynomial();
    const latestPolynomialId = latestPolynomial.getPolynomialID();
    const currentShareIndexes = Object.keys(this.shares[latestPolynomialId]);
    return currentShareIndexes;
  }

  getKeyDetails(): KeyDetails {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    const poly = this.metadata.getLatestPublicPolynomial();
    const previousPolyID = poly.getPolynomialID();
    const requiredShares = poly.getThreshold() - Object.keys(this.shares[previousPolyID]).length;

    let shareDescriptions = this.metadata.getShareDescription();
    if (shareDescriptions) {
      const existingShareIndexes = this.metadata.getShareIndexesForPolynomial(previousPolyID);
      shareDescriptions = Object.keys(shareDescriptions).reduce((acc: Record<string, string[]>, index: string) => {
        if (existingShareIndexes.indexOf(index) >= 0) acc[index] = shareDescriptions[index];
        return acc;
      }, {});
    }

    return {
      pubKey: this.metadata.pubKey,
      ed25519PublicKey: this.getEd25519PublicKey(),
      requiredShares,
      threshold: poly.getThreshold(),
      totalShares: this.metadata.getShareIndexesForPolynomial(previousPolyID).length,
      shareDescriptions,
    };
  }

  // Auth functions

  generateAuthMetadata(params: { input: Metadata[] }): AuthMetadata[] {
    const { input } = params;
    const authMetadatas = [];
    for (let i = 0; i < input.length; i += 1) {
      authMetadatas.push(new AuthMetadata(input[i], this.privKey));
    }
    return authMetadatas;
  }

  setAuthMetadata(params: { input: Metadata; serviceProvider?: IServiceProvider; privKey?: bigint }): Promise<{
    message: string;
  }> {
    const { input, serviceProvider, privKey } = params;
    const authMetadata = new AuthMetadata(input, this.privKey);
    return this.storageLayer.setMetadata({ input: authMetadata, serviceProvider, privKey });
  }

  async setAuthMetadataBulk(params: { input: Metadata[]; serviceProvider?: IServiceProvider; privKey?: bigint[] }): Promise<void> {
    if (!this.privKey) {
      throw CoreError.privateKeyUnavailable();
    }
    const { input, serviceProvider, privKey } = params;
    const authMetadatas = [] as AuthMetadata[];
    for (let i = 0; i < input.length; i += 1) {
      authMetadatas.push(new AuthMetadata(input[i], this.privKey));
    }
    await this.addLocalMetadataTransitions({ input: authMetadatas, serviceProvider, privKey });
  }

  async getAuthMetadata(params: {
    serviceProvider?: IServiceProvider;
    privKey?: bigint;
    includeLocalMetadataTransitions?: boolean;
  }): Promise<Metadata> {
    const raw = await this.getGenericMetadataWithTransitionStates({ ...params, fromJSONConstructor: AuthMetadata });
    const authMetadata = raw as AuthMetadata;
    return authMetadata.metadata;
  }

  // fetches the latest metadata potentially searching in local transition states first
  async getGenericMetadataWithTransitionStates(params: {
    fromJSONConstructor: FromJSONConstructor;
    serviceProvider?: IServiceProvider;
    privKey?: bigint;
    includeLocalMetadataTransitions?: boolean;
    _localMetadataTransitions?: LocalMetadataTransitions;
  }): Promise<unknown> {
    if (!((params.serviceProvider && params.serviceProvider.postboxKey.toString(16) !== "0") || params.privKey)) {
      throw CoreError.default("require either serviceProvider or priv key in getGenericMetadataWithTransitionStates");
    }
    if (params.includeLocalMetadataTransitions) {
      const transitions: LocalMetadataTransitions = params._localMetadataTransitions
        ? params._localMetadataTransitions
        : this._localMetadataTransitions;
      let index = null;
      for (let i = transitions[0].length - 1; i >= 0; i -= 1) {
        const x = transitions[0][i];
        if (params.privKey && x && x === params.privKey) index = i;
        else if (params.serviceProvider && !x) index = i;
        if (index !== null) break;
      }
      if (index !== null) {
        return transitions[1][index];
      }
    }
    let raw: IMessageMetadata;
    try {
      raw = await this.storageLayer.getMetadata(params);
    } catch (err: unknown) {
      const prettyError = await prettyPrintError(err);
      throw CoreError.metadataGetFailed(prettyError.message);
    }
    if ((raw as IMessageMetadata).message === SHARE_DELETED) {
      throw CoreError.fromCode(1308);
    }
    return params.fromJSONConstructor.fromJSON(raw);
  }

  // Lock functions
  async acquireWriteMetadataLock(): Promise<number> {
    if (this.haveWriteMetadataLock) return this.metadata.nonce;
    if (!this.privKey) {
      throw CoreError.privateKeyUnavailable();
    }

    // we check the metadata of a random share we have on the latest polynomial we know that reflects the cloud
    // below we cater for if we have an existing share or need to create the share in the SDK
    let randomShareStore: ShareStore;
    const latestPolyIDOnCloud = this.lastFetchedCloudMetadata.getLatestPublicPolynomial().getPolynomialID();
    const shareIndexesExistInSDK = Object.keys(this.shares[latestPolyIDOnCloud]);
    const randomIndex = shareIndexesExistInSDK[Math.floor(Math.random() * (shareIndexesExistInSDK.length - 1))];
    if (shareIndexesExistInSDK.length >= 1) {
      randomShareStore = this.shares[latestPolyIDOnCloud][randomIndex];
    } else {
      randomShareStore = this.outputShareStore(randomIndex, latestPolyIDOnCloud);
    }
    const latestRes = await this.catchupToLatestShare({ shareStore: randomShareStore });
    const latestMetadata = latestRes.shareMetadata;

    // read errors for what each means
    if (latestMetadata.nonce > this.lastFetchedCloudMetadata.nonce) {
      throw CoreError.acquireLockFailed(`unable to acquire write access for metadata due to 
      lastFetchedCloudMetadata (${this.lastFetchedCloudMetadata.nonce})
           being lower than last written metadata nonce (${latestMetadata.nonce}). perhaps update metadata SDK (create new tKey and init)`);
    } else if (latestMetadata.nonce < this.lastFetchedCloudMetadata.nonce) {
      throw CoreError.acquireLockFailed(`unable to acquire write access for metadata due to 
      lastFetchedCloudMetadata (${this.lastFetchedCloudMetadata.nonce})
      being higher than last written metadata nonce (${latestMetadata.nonce}). this should never happen as it 
      should only ever be updated by getting metadata)`);
    }

    const res = await this.storageLayer.acquireWriteLock({ privKey: this.privKey });
    if (res.status !== 1) throw CoreError.acquireLockFailed(`lock cannot be acquired from storage layer status code: ${res.status}`);

    // increment metadata nonce for write session
    // this.metadata.nonce += 1;
    this.haveWriteMetadataLock = res.id;
    return this.metadata.nonce;
  }

  async releaseWriteMetadataLock(): Promise<void> {
    if (!this.haveWriteMetadataLock) throw CoreError.releaseLockFailed("releaseWriteMetadataLock - don't have metadata lock to release");
    const res = await this.storageLayer.releaseWriteLock({ privKey: this.privKey, id: this.haveWriteMetadataLock });
    if (res.status !== 1) throw CoreError.releaseLockFailed(`lock cannot be released from storage layer status code: ${res.status}`);
    this.haveWriteMetadataLock = "";
  }

  // Module functions

  async _syncShareMetadata(adjustScopedStore?: (ss: unknown) => unknown): Promise<void> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }

    const shareArray = this.getAllShareStoresForLatestPolynomial().map((x) => x.share.share);
    await this.syncMultipleShareMetadata(shareArray, adjustScopedStore);
  }

  async syncMultipleShareMetadata(shares: bigint[], adjustScopedStore?: (ss: unknown) => unknown): Promise<void> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    this.metadata.nonce += 1;

    const newMetadataPromise = shares.map(async (share) => {
      const newMetadata: Metadata = this.metadata.clone();
      let specificShareMetadata: Metadata;
      try {
        specificShareMetadata = await this.getAuthMetadata({ privKey: share, includeLocalMetadataTransitions: true });
      } catch (err: unknown) {
        const prettyError = await prettyPrintError(err);
        throw CoreError.authMetadataGetUnavailable(prettyError.message);
      }

      let scopedStoreToBeSet: Record<string, unknown>;
      if (adjustScopedStore) {
        scopedStoreToBeSet = adjustScopedStore(specificShareMetadata.scopedStore) as Record<string, unknown>;
      } else {
        scopedStoreToBeSet = specificShareMetadata.scopedStore;
      }
      newMetadata.scopedStore = scopedStoreToBeSet;
      return newMetadata;
    });
    const newMetadata = await Promise.all(newMetadataPromise);
    return this.setAuthMetadataBulk({ input: newMetadata, privKey: shares });
  }

  _addRefreshMiddleware(
    moduleName: string,
    middleware: (generalStore: unknown, oldShareStores: ShareStoreMap, newShareStores: ShareStoreMap) => unknown
  ): void {
    this._refreshMiddleware[moduleName] = middleware;
  }

  _addReconstructKeyMiddleware(moduleName: string, middleware: () => Promise<bigint[]>): void {
    this._reconstructKeyMiddleware[moduleName] = middleware;
  }

  _addShareSerializationMiddleware(
    serialize: (share: bigint, type: string) => Promise<unknown>,
    deserialize: (serializedShare: unknown, type: string) => Promise<bigint>
  ): void {
    this._shareSerializationMiddleware = {
      serialize,
      deserialize,
    };
  }

  _setDeviceStorage(storeDeviceStorage: (deviceShareStore: ShareStore) => Promise<void>): void {
    if (this.storeDeviceShare) {
      throw CoreError.default("storeDeviceShare already set");
    }
    this.storeDeviceShare = storeDeviceStorage;
  }

  async addShareDescription(shareIndex: string, description: string, updateMetadata?: boolean): Promise<void> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    this.metadata.addShareDescription(shareIndex, description);
    if (updateMetadata) {
      await this._syncShareMetadata();
    }
  }

  async deleteShareDescription(shareIndex: string, description: string, updateMetadata?: boolean): Promise<void> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    this.metadata.deleteShareDescription(shareIndex, description);
    if (updateMetadata) {
      await this._syncShareMetadata();
    }
  }

  async updateShareDescription(shareIndex: string, oldDescription: string, newDescription: string, updateMetadata?: boolean): Promise<void> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    this.metadata.updateShareDescription(shareIndex, oldDescription, newDescription);
    if (updateMetadata) {
      await this._syncShareMetadata();
    }
  }

  async encrypt(data: Uint8Array): Promise<EncryptedMessage> {
    if (!this.privKey) throw CoreError.privateKeyUnavailable();
    return encrypt(getPubKeyECC(this.privKey), data);
  }

  async decrypt(encryptedMessage: EncryptedMessage): Promise<Uint8Array> {
    if (!this.privKey) throw CoreError.privateKeyUnavailable();
    return decrypt(toPrivKeyECC(this.privKey), encryptedMessage);
  }

  async _setTKeyStoreItem(moduleName: string, data: TkeyStoreItemType): Promise<void> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    const rawTkeyStoreItems: EncryptedMessage[] = (this.metadata.getTkeyStoreDomain(moduleName) as EncryptedMessage[]) || [];
    const decryptedItems = await Promise.all(
      rawTkeyStoreItems.map(async (x) => {
        const decryptedItem = await this.decrypt(x);
        return JSON.parse(bytesToUtf8(decryptedItem)) as TkeyStoreItemType;
      })
    );
    const encryptedData = await this.encrypt(utf8ToBytes(stringify(data, { replacer: bigIntReplacer })));
    const duplicateItemIndex = decryptedItems.findIndex((x) => x.id === data.id);
    if (duplicateItemIndex > -1) {
      rawTkeyStoreItems[duplicateItemIndex] = encryptedData;
    } else {
      rawTkeyStoreItems.push(encryptedData);
    }

    // update metadataStore
    this.metadata.setTkeyStoreDomain(moduleName, rawTkeyStoreItems);
    await this._syncShareMetadata();
  }

  async _deleteTKeyStoreItem(moduleName: string, id: string): Promise<void> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    const rawTkeyStoreItems = (this.metadata.getTkeyStoreDomain(moduleName) as EncryptedMessage[]) || [];
    const decryptedItems = await Promise.all(
      rawTkeyStoreItems.map(async (x) => {
        const decryptedItem = await this.decrypt(x);
        return JSON.parse(bytesToUtf8(decryptedItem)) as TkeyStoreItemType;
      })
    );
    const finalItems = decryptedItems.filter((x) => x.id !== id);
    this.metadata.setTkeyStoreDomain(moduleName, finalItems);
    await this._syncShareMetadata();
  }

  async getTKeyStore(moduleName: string): Promise<TkeyStoreItemType[]> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    const rawTkeyStoreItems = (this.metadata.getTkeyStoreDomain(moduleName) as EncryptedMessage[]) || [];

    const decryptedItems = await Promise.all(
      rawTkeyStoreItems.map(async (x) => {
        const decryptedItem = await this.decrypt(x);
        return JSON.parse(bytesToUtf8(decryptedItem)) as TkeyStoreItemType;
      })
    );
    return decryptedItems;
  }

  async getTKeyStoreItem(moduleName: string, id: string): Promise<TkeyStoreItemType> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    const rawTkeyStoreItems = (this.metadata.getTkeyStoreDomain(moduleName) as EncryptedMessage[]) || [];

    const decryptedItems = await Promise.all(
      rawTkeyStoreItems.map(async (x) => {
        const decryptedItem = await this.decrypt(x);
        return JSON.parse(bytesToUtf8(decryptedItem)) as TkeyStoreItemType;
      })
    );
    const item = decryptedItems.find((x) => x.id === id);
    return item;
  }

  // Import export shares
  async outputShare(shareIndex: BigIntString, type?: string): Promise<unknown> {
    const { share } = this.outputShareStore(shareIndex).share;
    if (!type) return share;

    return this._shareSerializationMiddleware.serialize(share, type);
  }

  async inputShare(share: unknown, type?: string): Promise<void> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    let shareStore: ShareStore;
    if (!type) shareStore = this.metadata.shareToShareStore(share as bigint);
    else {
      const deserialized = await this._shareSerializationMiddleware.deserialize(share, type);
      shareStore = this.metadata.shareToShareStore(deserialized);
    }
    const pubPoly = this.metadata.getLatestPublicPolynomial();
    const pubPolyID = pubPoly.getPolynomialID();
    const fullShareIndexesList = this.metadata.getShareIndexesForPolynomial(pubPolyID);
    if (!fullShareIndexesList.includes(shareStore.share.shareIndex.toString(16))) {
      throw CoreError.default("Latest poly doesn't include this share");
    }
    await this.inputShareStoreSafe(shareStore);
  }

  toJSON(): StringifiedType {
    return {
      shares: this.shares,
      enableLogging: this.enableLogging,
      privKey: this.privKey ? this.privKey.toString(16) : undefined,
      ed25519Key: this.ed25519Key ? bytesToHex(this.ed25519Key) : undefined,
      metadata: this.metadata,
      lastFetchedCloudMetadata: this.lastFetchedCloudMetadata,
      _localMetadataTransitions: [
        this._localMetadataTransitions[0].map((x: bigint | undefined) => (x !== undefined ? x.toString(16) : null)),
        this._localMetadataTransitions[1],
      ],
      manualSync: this.manualSync,
      serviceProvider: this.serviceProvider,
      storageLayer: this.storageLayer,
    };
  }

  getAllShareStoresForLatestPolynomial(): ShareStore[] {
    const pubPoly = this.metadata.getLatestPublicPolynomial();
    const pubPolyID = pubPoly.getPolynomialID();
    const existingShareIndexes = this.metadata.getShareIndexesForPolynomial(pubPolyID);
    const threshold = pubPoly.getThreshold();

    const pointsArr = [];
    const sharesForExistingPoly = Object.keys(this.shares[pubPolyID]);
    if (sharesForExistingPoly.length < threshold) {
      throw CoreError.unableToReconstruct("not enough shares for polynomial reconstruction");
    }
    for (let i = 0; i < threshold; i += 1) {
      pointsArr.push(new Point(hexToBigInt(sharesForExistingPoly[i]), this.shares[pubPolyID][sharesForExistingPoly[i]].share.share));
    }
    const currentPoly = lagrangeInterpolatePolynomial(pointsArr);
    const allExistingShares = currentPoly.generateShares(existingShareIndexes.map((s) => hexToBigInt(s)));
    const shareArray = existingShareIndexes.map((shareIndex) => {
      return this.metadata.shareToShareStore(allExistingShares[shareIndex].share);
    });
    return shareArray;
  }

  /// Destructive method. All data will be wiped!
  async CRITICAL_deleteTkey(): Promise<void> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    if (!this.privKey) {
      throw CoreError.privateKeyUnavailable();
    }
    if (this._localMetadataTransitions[0].length > 0 || this._localMetadataTransitions[1].length > 0) {
      throw CoreError.default("Please sync all local state before calling this function");
    }

    // Construct all shares
    const shareArray = this.getAllShareStoresForLatestPolynomial();
    await this.addLocalMetadataTransitions({
      input: [...Array(shareArray.length).fill({ message: SHARE_DELETED, dateAdded: Date.now() }), { message: KEY_NOT_FOUND }],
      privKey: [...shareArray.map((x) => x.share.share), undefined],
    });
    await this.syncLocalMetadataTransitions(); // forcesync

    this.privKey = undefined;
    this.metadata = undefined;
    this.shares = {};
    this.lastFetchedCloudMetadata = undefined;
  }

  getApi(): ITKeyApi {
    return {
      getMetadata: this.getMetadata.bind(this),
      getStorageLayer: this.getStorageLayer.bind(this),
      initialize: this.initialize.bind(this),
      catchupToLatestShare: this.catchupToLatestShare.bind(this),
      _syncShareMetadata: this._syncShareMetadata.bind(this),
      _addRefreshMiddleware: this._addRefreshMiddleware.bind(this),
      _addReconstructKeyMiddleware: this._addReconstructKeyMiddleware.bind(this),
      _addShareSerializationMiddleware: this._addShareSerializationMiddleware.bind(this),
      addShareDescription: this.addShareDescription.bind(this),
      generateNewShare: this.generateNewShare.bind(this),
      inputShareStore: this.inputShareStore.bind(this),
      inputShareStoreSafe: this.inputShareStoreSafe.bind(this),
      outputShareStore: this.outputShareStore.bind(this),
      inputShare: this.inputShare.bind(this),
      outputShare: this.outputShare.bind(this),
      _setDeviceStorage: this._setDeviceStorage.bind(this),
      encrypt: this.encrypt.bind(this),
      decrypt: this.decrypt.bind(this),
      getTKeyStore: this.getTKeyStore.bind(this),
      getTKeyStoreItem: this.getTKeyStoreItem.bind(this),
      _setTKeyStoreItem: this._setTKeyStoreItem.bind(this),
      _deleteTKeyStoreItem: this._deleteTKeyStoreItem.bind(this),
      deleteShare: this.deleteShare.bind(this),
    };
  }

  private setModuleReferences() {
    Object.keys(this.modules).map((x) => this.modules[x].setModuleReferences(this.getApi()));
  }

  private async initializeModules() {
    return Promise.all(Object.keys(this.modules).map((x) => this.modules[x].initialize()));
  }

  private async _refreshShares(threshold: number, newShareIndexes: string[], previousPolyID: PolynomialID): Promise<RefreshSharesResult> {
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    if (!this.privKey) {
      throw CoreError.privateKeyUnavailable();
    }
    if (threshold > newShareIndexes.length) {
      throw CoreError.default(`threshold should not be greater than share indexes. ${threshold} > ${newShareIndexes.length}`);
    }

    // update metadata nonce
    this.metadata.nonce += 1;

    const poly = generateRandomPolynomial(threshold - 1, this.privKey);
    const shares = poly.generateShares(newShareIndexes.map((s) => hexToBigInt(s)));
    const existingShareIndexes = this.metadata.getShareIndexesForPolynomial(previousPolyID);

    const pointsArr = [];
    const sharesForExistingPoly = Object.keys(this.shares[previousPolyID]);
    if (sharesForExistingPoly.length < threshold) {
      throw CoreError.unableToReconstruct("not enough shares for polynomial reconstruction");
    }
    for (let i = 0; i < threshold; i += 1) {
      pointsArr.push(new Point(hexToBigInt(sharesForExistingPoly[i]), this.shares[previousPolyID][sharesForExistingPoly[i]].share.share));
    }
    const oldPoly = lagrangeInterpolatePolynomial(pointsArr);

    const shareIndexesNeedingEncryption: string[] = [];
    for (let index = 0; index < existingShareIndexes.length; index += 1) {
      const shareIndexHex = existingShareIndexes[index];
      // define shares that need encryption/relaying
      if (newShareIndexes.includes(shareIndexHex)) {
        shareIndexesNeedingEncryption.push(shareIndexHex);
      }
    }

    // add metadata new poly to metadata
    this.metadata.addFromPolynomialAndShares(poly, shares);

    // change to share stores for public storing
    const oldShareStores: Record<string, ShareStore> = {};
    const newShareStores: Record<string, ShareStore> = {};
    const polyID = poly.getPolynomialID();
    newShareIndexes.forEach((shareIndexHex) => {
      newShareStores[shareIndexHex] = new ShareStore(shares[shareIndexHex], polyID);
    });

    // evaluate oldPoly for old shares and set new metadata with encrypted share for new polynomial

    const m = this.metadata.clone();
    const newScopedStore: Record<string, EncryptedMessage> = {};
    const sharesToPush = await Promise.all(
      shareIndexesNeedingEncryption.map(async (shareIndex) => {
        const oldShare = oldPoly.polyEval(hexToBigInt(shareIndex));
        const encryptedShare = await encrypt(getPubKeyECC(oldShare), utf8ToBytes(JSON.stringify(newShareStores[shareIndex], bigIntReplacer)));
        newScopedStore[getPubKeyPoint(oldShare).x.toString(16)] = encryptedShare;
        oldShareStores[shareIndex] = new ShareStore(new Share(hexToBigInt(shareIndex), oldShare), previousPolyID);
        return oldShare;
      })
    );
    m.setScopedStore("encryptedShares", newScopedStore);
    const metadataToPush = Array(sharesToPush.length).fill(m);

    // run refreshShare middleware
    // If a shareIndex is left out during refresh shares, we assume that it being explicitly deleted.
    for (const moduleName in this._refreshMiddleware) {
      if (Object.prototype.hasOwnProperty.call(this._refreshMiddleware, moduleName)) {
        const adjustedGeneralStore = this._refreshMiddleware[moduleName](
          this.metadata.getGeneralStoreDomain(moduleName),
          oldShareStores,
          newShareStores
        );
        if (!adjustedGeneralStore) this.metadata.deleteGeneralStoreDomain(moduleName);
        else this.metadata.setGeneralStoreDomain(moduleName, adjustedGeneralStore);
      }
    }

    const newShareMetadataToPush: Metadata[] = [];
    const newShareStoreSharesToPush = newShareIndexes.map((shareIndex) => {
      const me = this.metadata.clone();
      newShareMetadataToPush.push(me);
      return newShareStores[shareIndex].share.share;
    });

    const AuthMetadatas = this.generateAuthMetadata({ input: [...metadataToPush, ...newShareMetadataToPush] });

    // Combine Authmetadata and service provider ShareStore
    await this.addLocalMetadataTransitions({
      input: [...AuthMetadatas, newShareStores["1"]],
      privKey: [...sharesToPush, ...newShareStoreSharesToPush, undefined],
    });

    // update this.shares with these new shares
    for (let index = 0; index < newShareIndexes.length; index += 1) {
      const shareIndex = newShareIndexes[index];
      this.inputShareStore(newShareStores[shareIndex]);
    }
    // await this.releaseWriteMetadataLock();
    return { shareStores: newShareStores };
  }

  private async _initializeNewKey({
    determinedShare,
    initializeModules,
    importedKey,
    importEd25519Seed,
    delete1OutOf1,
  }: {
    determinedShare?: bigint;
    initializeModules?: boolean;
    importedKey?: bigint;
    importEd25519Seed?: Uint8Array;
    delete1OutOf1?: boolean;
  } = {}): Promise<InitializeNewKeyResult> {
    this.lastFetchedCloudMetadata = undefined;

    if (!importedKey) {
      const tmpPriv = generatePrivateBigInt();
      this.secp256k1Key = tmpPriv;
    } else {
      this.secp256k1Key = importedKey;
    }

    // create a random poly and respective shares
    // 1 is defined as the serviceProvider share
    // 0 is for tKey
    const shareIndexForDeviceStorage = generatePrivateExcludingIndexes([1n, 0n]);

    const shareIndexes = [1n, shareIndexForDeviceStorage];
    let poly: Polynomial;
    if (determinedShare) {
      const shareIndexForDeterminedShare = generatePrivateExcludingIndexes([1n, 0n]);
      poly = generateRandomPolynomial(1, this.privKey, [new Share(shareIndexForDeterminedShare, determinedShare)]);
      shareIndexes.push(shareIndexForDeterminedShare);
    } else {
      poly = generateRandomPolynomial(1, this.privKey);
    }
    const shares = poly.generateShares(shareIndexes);

    // create metadata to be stored
    const metadata = new Metadata(getPubKeyPoint(this.privKey));
    metadata.addFromPolynomialAndShares(poly, shares);
    const serviceProviderShare = shares[shareIndexes[0].toString(16)];
    const shareStore = new ShareStore(serviceProviderShare, poly.getPolynomialID());
    this.metadata = metadata;

    // setup ed25519 seed after metadata is set
    // import/gen ed25519 seed
    await this.setupEd25519Seed(importEd25519Seed);

    // initialize modules
    if (initializeModules) {
      await this.initializeModules();
    }

    const metadataToPush: Metadata[] = [];
    const sharesToPush = shareIndexes.map((shareIndex) => {
      metadataToPush.push(this.metadata);
      return shares[shareIndex.toString(16)].share;
    });

    const authMetadatas = this.generateAuthMetadata({ input: metadataToPush });

    // because this is the first time we're setting metadata there is no need to acquire a lock
    // acquireLock: false. Force push
    await this.addLocalMetadataTransitions({ input: [...authMetadatas, shareStore], privKey: [...sharesToPush, undefined] });
    if (delete1OutOf1) {
      await this.addLocalMetadataTransitions({ input: [{ message: ONE_KEY_DELETE_NONCE }], privKey: [this.serviceProvider.postboxKey] });
    }

    // store metadata on metadata respective to shares
    for (let index = 0; index < shareIndexes.length; index += 1) {
      const shareIndex = shareIndexes[index];
      // also add into our share store
      this.inputShareStore(new ShareStore(shares[shareIndex.toString(16)], poly.getPolynomialID()));
    }

    if (this.storeDeviceShare) {
      await this.storeDeviceShare(new ShareStore(shares[shareIndexes[1].toString(16)], poly.getPolynomialID()));
    }

    const result: InitializeNewKeyResult = {
      secp256k1Key: this.privKey,
      deviceShare: new ShareStore(shares[shareIndexes[1].toString(16)], poly.getPolynomialID()),
      userShare: undefined,
    };
    if (determinedShare) {
      result.userShare = new ShareStore(shares[shareIndexes[2].toString(16)], poly.getPolynomialID());
    }
    return result;
  }

  private async importEd25519Seed(seed: Uint8Array): Promise<void> {
    if (!this.privKey) {
      throw CoreError.privateKeyUnavailable();
    }
    if (this.getEd25519PublicKey()) {
      throw CoreError.default("Ed25519 key already exists");
    }

    // derive key pair (scalar, public key point) from seed
    const keyPair = getEd25519KeyPairFromSeed(seed);

    this.metadata.setGeneralStoreDomain(ed25519SeedConst, {
      message: await this.encrypt(seed),
      publicKey: bytesToHex(encodeEd25519Point(keyPair.point)),
    });
    this._ed25519Seed = seed;
  }

  private async setupEd25519Seed(seed?: Uint8Array): Promise<void> {
    if (!this.privKey) {
      throw CoreError.privateKeyUnavailable();
    }
    let seedToUse = seed;
    if (!seed) {
      seedToUse = randomBytes(32);
    }
    await this.importEd25519Seed(seedToUse);
  }
}

export default ThresholdKey;
