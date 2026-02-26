import {
  decrypt,
  EllipticCurve,
  EllipticPoint,
  encrypt,
  EncryptedMessage,
  KeyDetails,
  KeyType,
  Point,
  ReconstructedKeyResult,
  secp256k1,
  StringifiedType,
  TKeyArgs,
  TKeyInitArgs,
} from "@tkey/common-types";
import { CoreError, TKey } from "@tkey/core";
import { post } from "@toruslabs/http-helpers";
import { hexToBytes, utf8ToBytes } from "@toruslabs/metadata-helpers";
import { dotProduct, ecPoint, hexPoint, PointHex, randomSelection, RSSClient } from "@toruslabs/rss-client";
import { getEd25519ExtendedPublicKey as getEd25519KeyPairFromSeed, getKeyCurve, getSecpKeyFromEd25519 } from "@toruslabs/torus.js";
import BN from "bn.js";
import { ec as EC } from "elliptic";
import { keccak256 } from "ethereum-cryptography/keccak";

import { TSSTorusServiceProvider } from ".";
import {
  CopyRemoteTssParams,
  FactorEnc,
  IAccountSaltStore,
  InitializeNewTSSKeyResult,
  IRemoteClientState,
  RefreshRemoteTssParams,
  RefreshRemoteTssReturnType,
} from "./common";
import {
  generateSalt,
  getEd25519SeedStoreDomainKey,
  getLagrangeCoeffs,
  getPubKeyPoint,
  kCombinations,
  lagrangeInterpolation,
  pointToHex,
} from "./util";

export const TSS_MODULE = "tssModule";
export const TSS_TAG_DEFAULT = "default";

export const FACTOR_KEY_TYPE = "secp256k1";
export const factorKeyCurve = new EC(FACTOR_KEY_TYPE);

export const LEGACY_KEY_TYPE = "secp256k1";

export interface TSSTKeyArgs extends TKeyArgs {
  serviceProvider: TSSTorusServiceProvider;
  tssKeyType: KeyType;
  tssTag?: string;
}

export interface TKeyTSSInitArgs extends TKeyInitArgs {
  deviceTSSShare?: BN;
  deviceTSSIndex?: number;
  factorPub?: Point;
  skipTssInit?: boolean;
}

export class TKeyTSS extends TKey {
  serviceProvider: TSSTorusServiceProvider = null;

  private _tssKeyType: KeyType;

  private _tssCurve: EC;

  private _tssTag: string;

  private _accountSalt: string;

  /**
   * Constructs a new TKeyTSS instance using the given parameters.
   */
  constructor(args: TSSTKeyArgs) {
    super(args);
    const { serviceProvider, storageLayer, tssTag = "default", tssKeyType } = args;

    if (serviceProvider.customAuthArgs.keyType !== tssKeyType) {
      throw CoreError.default(`service provider keyType mismatch: ${serviceProvider.customAuthArgs.keyType} !== ${tssKeyType}`);
    }

    this.serviceProvider = serviceProvider;
    this.storageLayer = storageLayer;
    this._tssTag = tssTag;
    this._tssKeyType = tssKeyType;
    this._tssCurve = new EC(tssKeyType);
  }

  public get tssTag(): string {
    return this._tssTag;
  }

  public get tssKeyType(): KeyType {
    return this._tssKeyType;
  }

  public get tssCurve(): EllipticCurve {
    return this._tssCurve;
  }

  public set tssTag(tag: string) {
    if ((this.metadata.tssKeyTypes[this.tssTag] || LEGACY_KEY_TYPE) !== this.tssKeyType) {
      throw CoreError.default(`tssKeyType mismatch: ${this.metadata.tssKeyTypes[this.tssTag]} !== ${this.tssKeyType}`);
    }
    this._tssTag = tag;
  }

  static async fromJSON(value: StringifiedType, args: TSSTKeyArgs): Promise<TKeyTSS> {
    const tbTss = new TKeyTSS(args);
    const tb = await super.fromJSON(value, args);

    const { tssTag, tssKeyType, accountSalt } = value;

    if (tssTag !== tbTss.tssTag) {
      throw CoreError.default(`tssTag mismatch: ${tssTag} !== ${tbTss.tssTag}`);
    }

    if (tssKeyType !== tbTss.tssKeyType) {
      throw CoreError.default(`tssKeyType mismatch: ${tssKeyType} !== ${tbTss.tssKeyType}`);
    }

    // copy over tkey to tkeyTss
    tbTss.shares = tb.shares;
    tbTss.metadata = tb.metadata;
    tbTss.lastFetchedCloudMetadata = tb.lastFetchedCloudMetadata;
    tbTss._localMetadataTransitions = tb._localMetadataTransitions;

    // this will be computed during reconstruct tkey
    // should we restore here?
    tbTss._accountSalt = accountSalt;
    tbTss.secp256k1Key = tb.secp256k1Key;
    tbTss.ed25519Key = tb.ed25519Key;

    return tbTss;
  }

  toJSON(): StringifiedType {
    const tbJson = super.toJSON();
    tbJson.tssTag = this.tssTag;
    tbJson.tssKeyType = this.tssKeyType;
    tbJson.accountSalt = this._accountSalt;
    return tbJson;
  }

  /**
   * Initializes this instance. If a TSS account does not exist, creates one
   * under the given factor key. `skipTssInit` skips TSS account creation and
   * can be used with `importTssKey` to just import an existing account instead.
   * @returns The key details of TKey core.
   */
  async initialize(params?: TKeyTSSInitArgs): Promise<KeyDetails> {
    const keyDetails = await super.initialize(params);

    if (!this.metadata.tssPolyCommits[this.tssTag] && !(params?.skipTssInit || params?.neverInitializeNewKey)) {
      // if tss shares have not been created for this tssTag, create new tss sharing
      const { factorEncs, factorPubs, tssPolyCommits } = await this._initializeNewTSSKey(
        this.tssTag,
        params.deviceTSSShare,
        params.factorPub,
        params.deviceTSSIndex
      );
      this.metadata.updateTSSData({ tssKeyType: this._tssKeyType, tssTag: this.tssTag, tssNonce: 0, tssPolyCommits, factorPubs, factorEncs });
      const accountSalt = generateSalt(this._tssCurve);
      await this._setTKeyStoreItem(TSS_MODULE, {
        id: "accountSalt",
        value: accountSalt,
      } as IAccountSaltStore);
      this._accountSalt = accountSalt;
    }

    if (this.metadata.tssPolyCommits[this.tssTag] && (this.metadata.tssKeyTypes[this.tssTag] || LEGACY_KEY_TYPE) !== this.tssKeyType) {
      throw CoreError.default(`tssKeyType mismatch: ${this.metadata.tssKeyTypes[this.tssTag]} !== ${this.tssKeyType}`);
    }

    return keyDetails;
  }

  /**
   * Returns the encrypted data associated with the given factor public key.
   */
  getFactorEncs(factorPub: Point): FactorEnc {
    if (!this.metadata) throw CoreError.metadataUndefined();
    if (!this.metadata.factorEncs) throw CoreError.default("no factor encs mapping");
    if (!this.metadata.factorPubs) throw CoreError.default("no factor pubs mapping");
    const factorPubs = this.metadata.factorPubs[this.tssTag];
    if (!factorPubs) throw CoreError.default(`no factor pubs for this tssTag ${this.tssTag}`);
    if (factorPubs.filter((f) => f.x.cmp(factorPub.x) === 0 && f.y.cmp(factorPub.y) === 0).length === 0)
      throw CoreError.default(`factor pub ${factorPub} not found for tssTag ${this.tssTag}`);
    if (!this.metadata.factorEncs[this.tssTag]) throw CoreError.default(`no factor encs for tssTag ${this.tssTag}`);
    const factorPubID = factorPub.x.toString(16, 64);
    return this.metadata.factorEncs[this.tssTag][factorPubID];
  }

  /**
   * Returns the TSS share associated with the given factor private key.
   */
  async getTSSShare(
    factorKey: BN,
    opts?: {
      threshold?: number;
      accountIndex?: number;
      coefficient?: BN;
    }
  ): Promise<{
    tssIndex: number;
    tssShare: BN;
  }> {
    const factorPub = getPubKeyPoint(factorKey, factorKeyCurve);
    const factorEncs = this.getFactorEncs(factorPub);
    const { userEnc, serverEncs, tssIndex, type } = factorEncs;
    const factorKeyBytes = hexToBytes(factorKey.toString(16, 64));
    const userDecryption = await decrypt(factorKeyBytes, userEnc);
    const serverDecryptions = await Promise.all(
      serverEncs.map((factorEnc) => {
        if (factorEnc === null) return null;
        return decrypt(factorKeyBytes, factorEnc);
      })
    );
    const tssShareBufs = [userDecryption].concat(serverDecryptions);

    const tssShareBNs = tssShareBufs.map((buf) => {
      if (buf === null) return null;
      return new BN(buf);
    });

    const ec = this._tssCurve;
    const tssCommits = this.getTSSCommits().map((p) => {
      return ec.keyFromPublic({ x: p.x.toString(16, 64), y: p.y.toString(16, 64) }).getPublic();
    });

    const userDec = tssShareBNs[0];

    const accountIndex = opts?.accountIndex || 0;
    const coefficient = opts?.coefficient || new BN(1);
    if (type === "direct") {
      const tssSharePub = ec.g.mul(userDec);
      const tssCommitA0 = tssCommits[0];
      const tssCommitA1 = tssCommits[1];
      const _tssSharePub = tssCommitA0.add(tssCommitA1.mul(new BN(tssIndex)));
      if (tssSharePub.eq(_tssSharePub)) {
        const adjustedShare = this.adjustTssShare(userDec, accountIndex, coefficient);
        return { tssIndex, tssShare: adjustedShare };
      }
      throw new Error("user decryption does not match tss commitments...");
    }

    // if type === "hierarchical"
    const serverDecs = tssShareBNs.slice(1); // 5 elems
    const serverIndexes = new Array(serverDecs.length).fill(null).map((_, i) => i + 1);

    const threshold = opts?.threshold || Math.ceil(serverDecs.length / 2);
    const combis = kCombinations(serverDecs.length, threshold);
    for (let i = 0; i < combis.length; i++) {
      const combi = combis[i];
      const selectedServerDecs = serverDecs.filter((_, j) => combi.indexOf(j) > -1);
      if (selectedServerDecs.includes(null)) continue;

      const selectedServerIndexes = serverIndexes.filter((_, j) => combi.indexOf(j) > -1);
      const serverLagrangeCoeffs = selectedServerIndexes.map((x) => getLagrangeCoeffs(ec, selectedServerIndexes, x));
      const serverInterpolated = dotProduct(serverLagrangeCoeffs, selectedServerDecs, ec.n);
      const lagrangeCoeffs = [getLagrangeCoeffs(ec, [1, 99], 1), getLagrangeCoeffs(ec, [1, 99], 99)];
      const tssShare = dotProduct(lagrangeCoeffs, [serverInterpolated, userDec], ec.n);
      const tssSharePub = ec.g.mul(tssShare);
      const tssCommitA0 = tssCommits[0];
      const tssCommitA1 = tssCommits[1];
      let _tssSharePub = tssCommitA0;
      for (let j = 0; j < tssIndex; j++) {
        _tssSharePub = _tssSharePub.add(tssCommitA1);
      }
      if (tssSharePub.eq(_tssSharePub)) {
        const adjustedShare = this.adjustTssShare(tssShare, accountIndex, coefficient);
        return { tssIndex, tssShare: adjustedShare };
      }
    }
    throw new Error("could not find any combination of server decryptions that match tss commitments...");
  }

  /**
   * Returns the TSS public key and the curve points corresponding to secret key
   * shares, as stored in Metadata.
   */
  getTSSCommits(): Point[] {
    if (!this.metadata) throw CoreError.metadataUndefined();
    const tssPolyCommits = this.metadata.tssPolyCommits[this.tssTag];
    if (!tssPolyCommits) throw CoreError.default(`tss poly commits not found for tssTag ${this.tssTag}`);
    if (tssPolyCommits.length === 0) throw CoreError.default("tss poly commits is empty");
    return tssPolyCommits;
  }

  /**
   * Returns the TSS public key.
   */
  getTSSPub(accountIndex?: number): Point {
    const ec = this._tssCurve;
    const tssCommits = this.getTSSCommits();
    if (accountIndex && accountIndex > 0) {
      // Add account nonce to pub key.
      const nonce = this.computeAccountNonce(accountIndex);
      const noncePub = ec.keyFromPrivate(nonce.toString("hex")).getPublic();
      const pubKeyPoint = tssCommits[0].toEllipticPoint(ec);
      const devicePubKeyPoint = pubKeyPoint.add(noncePub);
      return Point.fromElliptic(devicePubKeyPoint);
    }
    return tssCommits[0];
  }

  /**
   * Returns the node details for RSS.
   */
  async _getRssNodeDetails(): Promise<{
    serverEndpoints: string[];
    serverPubKeys: PointHex[];
    serverThreshold: number;
  }> {
    const { serverEndpoints, serverPubKeys, serverThreshold } = await this.serviceProvider.getRSSNodeDetails();
    if (!Array.isArray(serverEndpoints) || serverEndpoints.length === 0) throw new Error("service provider tss server endpoints are missing");
    if (!Array.isArray(serverPubKeys) || serverPubKeys.length === 0) throw new Error("service provider pub keys are missing");
    return {
      serverEndpoints,
      serverPubKeys,
      serverThreshold: serverThreshold || Math.floor(serverEndpoints.length / 2) + 1,
    };
  }

  /**
   * Imports an existing private key for threshold signing. A corresponding user
   * key share will be stored under the specified factor key.
   */
  async importTssKey(
    params: {
      tag: string;
      importKey: Uint8Array;
      factorPub: Point;
      newTSSIndex: number;
    },
    serverOpts: {
      selectedServers?: number[];
      authSignatures: string[];
    }
  ): Promise<void> {
    const ec = this._tssCurve;
    if (!this.secp256k1Key) throw CoreError.privateKeyUnavailable();
    if (!this.metadata) {
      throw CoreError.metadataUndefined();
    }
    const { importKey, factorPub, newTSSIndex, tag } = params;

    const oldTag = this.tssTag;
    this._tssTag = tag;

    try {
      const { selectedServers = [], authSignatures = [] } = serverOpts || {};

      if (!tag) throw CoreError.default(`invalid param, tag is required`);
      if (!factorPub) throw CoreError.default(`invalid param, newFactorPub is required`);
      if (!newTSSIndex) throw CoreError.default(`invalid param, newTSSIndex is required`);
      if (authSignatures.length === 0) throw CoreError.default(`invalid param, authSignatures is required`);

      const existingFactorPubs = this.metadata.factorPubs[tag];
      if (existingFactorPubs?.length > 0) {
        throw CoreError.default(`Duplicate account tag, please use a unique tag for importing key`);
      }
      const factorPubs = [factorPub];

      const importScalar = await (async () => {
        if (this._tssKeyType === KeyType.secp256k1) {
          return new BN(importKey);
        } else if (this._tssKeyType === KeyType.ed25519) {
          // Store seed in metadata.
          const domainKey = getEd25519SeedStoreDomainKey(this.tssTag || TSS_TAG_DEFAULT);
          const result = this.metadata.getGeneralStoreDomain(domainKey) as Record<string, unknown>;
          if (result) {
            throw new Error("Seed already exists");
          }

          const { scalar } = getEd25519KeyPairFromSeed(importKey);
          const encKey = new Uint8Array(getKeyCurve(KeyType.secp256k1).Point.fromAffine(getSecpKeyFromEd25519(scalar).point).toBytes(true));
          const msg = await encrypt(encKey, importKey);
          this.metadata.setGeneralStoreDomain(domainKey, { message: msg });

          return new BN(scalar.toString(16), 16);
        }
        throw new Error("Invalid key type");
      })();

      if (!importScalar || importScalar.eq(new BN("0"))) {
        throw new Error("Invalid importedKey");
      }

      const tssIndexes = [newTSSIndex];
      const existingNonce = this.metadata.tssNonces[this.tssTag];
      const newTssNonce: number = existingNonce && existingNonce > 0 ? existingNonce + 1 : 0;
      const verifierAndVerifierID = this.serviceProvider.getVerifierNameVerifierId();
      const label = `${verifierAndVerifierID}\u0015${this.tssTag}\u0016${newTssNonce}`;
      const tssPubKey = hexPoint(ec.g.mul(importScalar));
      const rssNodeDetails = await this._getRssNodeDetails();
      const { pubKey: newTSSServerPub, nodeIndexes } = await this.serviceProvider.getTSSPubKey(this.tssTag, newTssNonce);
      let finalSelectedServers = selectedServers;

      if (nodeIndexes?.length > 0) {
        if (selectedServers.length) {
          finalSelectedServers = nodeIndexes.slice(0, Math.min(selectedServers.length, nodeIndexes.length));
        } else {
          finalSelectedServers = nodeIndexes.slice(0, 3);
        }
      } else if (selectedServers?.length === 0) {
        finalSelectedServers = randomSelection(
          new Array(rssNodeDetails.serverEndpoints.length).fill(null).map((_, i) => i + 1),
          Math.ceil(rssNodeDetails.serverEndpoints.length / 2)
        );
      }

      const { serverEndpoints, serverPubKeys, serverThreshold } = rssNodeDetails;

      const rssClient = new RSSClient({
        serverEndpoints,
        serverPubKeys,
        serverThreshold,
        tssPubKey,
        keyType: this._tssKeyType,
      });

      const refreshResponses = await rssClient.import({
        importKey: importScalar,
        dkgNewPub: pointToHex(newTSSServerPub),
        selectedServers: finalSelectedServers,
        factorPubs: factorPubs.map((f) => pointToHex(f)),
        targetIndexes: tssIndexes,
        newLabel: label,
        sigs: authSignatures,
      });
      const secondCommit = newTSSServerPub.toEllipticPoint(ec).add(ecPoint(ec, tssPubKey).neg());
      const newTSSCommits = [
        Point.fromJSON(tssPubKey),
        Point.fromJSON({ x: secondCommit.getX().toString(16, 64), y: secondCommit.getY().toString(16, 64) }),
      ];
      const factorEncs: {
        [factorPubID: string]: FactorEnc;
      } = {};
      for (let i = 0; i < refreshResponses.length; i++) {
        const refreshResponse = refreshResponses[i];
        factorEncs[refreshResponse.factorPub.x.padStart(64, "0")] = {
          type: "hierarchical",
          tssIndex: refreshResponse.targetIndex,
          userEnc: refreshResponse.userFactorEnc,
          serverEncs: refreshResponse.serverFactorEncs,
        };
      }
      this.metadata.updateTSSData({
        tssKeyType: this._tssKeyType,
        tssTag: this.tssTag,
        tssNonce: newTssNonce,
        tssPolyCommits: newTSSCommits,
        factorPubs,
        factorEncs,
      });
      if (!this._accountSalt) {
        const accountSalt = generateSalt(this._tssCurve);
        await this._setTKeyStoreItem(TSS_MODULE, {
          id: "accountSalt",
          value: accountSalt,
        } as IAccountSaltStore);
        this._accountSalt = accountSalt;
      }
      await this._syncShareMetadata();
    } catch (error) {
      this._tssTag = oldTag;
      throw error;
    }
  }

  /**
   * UNSAFE: USE WITH CAUTION
   *
   * Reconstructs and exports the TSS private key.
   */
  async _UNSAFE_exportTssKey(tssOptions: {
    factorKey: BN;
    selectedServers?: number[];
    authSignatures: string[];
    accountIndex?: number;
  }): Promise<BN> {
    if (!this.metadata) throw CoreError.metadataUndefined("metadata is undefined");
    if (!this.secp256k1Key) throw new Error("Tkey is not reconstructed");
    if (!this.metadata.tssPolyCommits[this.tssTag]) throw new Error(`tss key has not been initialized for tssTag ${this.tssTag}`);

    const { factorKey, selectedServers, authSignatures, accountIndex } = tssOptions;

    const { tssIndex } = await this.getTSSShare(factorKey);
    // Assumption that there are only index 2 and 3 for tss shares
    // create complement index share
    const tempShareIndex = tssIndex === 2 ? 3 : 2;
    const tempFactorKey = factorKeyCurve.genKeyPair().getPrivate();
    const tempFactorPub = getPubKeyPoint(tempFactorKey, factorKeyCurve);

    await this.addFactorPub({
      existingFactorKey: factorKey,
      newFactorPub: tempFactorPub,
      newTSSIndex: tempShareIndex,
      authSignatures,
      selectedServers,
      refreshShares: true,
    });

    const { tssShare: factorShare, tssIndex: factorIndex } = await this.getTSSShare(factorKey);
    const { tssShare: tempShare, tssIndex: tempIndex } = await this.getTSSShare(tempFactorKey);

    // reconstruct final key using sss
    const ec = this._tssCurve;
    const tssKey = lagrangeInterpolation(ec, [tempShare, factorShare], [new BN(tempIndex), new BN(factorIndex)]);

    // delete created tss share
    await this.deleteFactorPub({
      factorKey,
      deleteFactorPub: tempFactorPub,
      authSignatures,
      selectedServers,
    });

    // Derive key for account index.
    const nonce = this.computeAccountNonce(accountIndex);
    const derivedKey = tssKey.add(nonce).umod(this._tssCurve.n);

    return derivedKey;
  }

  /**
   * UNSAFE: USE WITH CAUTION
   *
   * Reconstructs the TSS private key and exports the ed25519 private key seed.
   */
  async _UNSAFE_exportTssEd25519Seed(tssOptions: { factorKey: BN; selectedServers?: number[]; authSignatures: string[] }): Promise<Uint8Array> {
    const edScalar = await this._UNSAFE_exportTssKey(tssOptions);

    // Try to export ed25519 seed. This is only available if import key was being used.
    const domainKey = getEd25519SeedStoreDomainKey(this.tssTag || TSS_TAG_DEFAULT);
    const result = this.metadata.getGeneralStoreDomain(domainKey) as Record<string, EncryptedMessage>;

    const decKey = getSecpKeyFromEd25519(BigInt(`0x${edScalar.toString(16)}`)).scalar;
    const decKeyBytes = hexToBytes(decKey.toString(16).padStart(64, "0"));

    const seed = await decrypt(decKeyBytes, result.message);
    return seed;
  }

  // remote signer function

  /**
   * Refreshes TSS shares. Allows to change number of shares. New user shares are
   * only produced for the target indices.
   * @param factorPubs - Factor pub keys after refresh.
   * @param tssIndices - Target tss indices to generate new shares for.
   * @param remoteFactorPub - Factor Pub for remote share.
   * @param signatures - Signatures for authentication against RSS servers.
   */
  async remoteRefreshTssShares(params: { factorPubs: Point[]; tssIndices: number[]; remoteClient: IRemoteClientState }) {
    const { factorPubs, tssIndices, remoteClient } = params;
    const rssNodeDetails = await this._getRssNodeDetails();
    const { serverEndpoints, serverPubKeys, serverThreshold } = rssNodeDetails;
    let finalSelectedServers = randomSelection(
      new Array(rssNodeDetails.serverEndpoints.length).fill(null).map((_, i) => i + 1),
      Math.ceil(rssNodeDetails.serverEndpoints.length / 2)
    );

    const verifierNameVerifierId = this.serviceProvider.getVerifierNameVerifierId();

    const tssCommits = this.metadata.tssPolyCommits[this.tssTag];
    const tssNonce: number = this.metadata.tssNonces[this.tssTag] || 0;
    const { pubKey: newTSSServerPub, nodeIndexes } = await this.serviceProvider.getTSSPubKey(this.tssTag, tssNonce + 1);
    // move to pre-refresh
    if (nodeIndexes?.length > 0) {
      finalSelectedServers = nodeIndexes.slice(0, Math.min(serverEndpoints.length, nodeIndexes.length));
    }

    const factorEnc = this.getFactorEncs(Point.fromSEC1(secp256k1, remoteClient.remoteFactorPub));

    const dataRequired: RefreshRemoteTssParams = {
      factorEnc,
      factorPubs: factorPubs.map((pub) => pub.toPointHex()),
      targetIndexes: tssIndices,
      verifierNameVerifierId,
      tssTag: this.tssTag,
      tssCommits: tssCommits.map((commit) => commit.toPointHex()),
      tssNonce,
      newTSSServerPub: newTSSServerPub.toPointHex(),
      serverOpts: {
        selectedServers: finalSelectedServers,
        serverEndpoints,
        serverPubKeys,
        serverThreshold,
        authSignatures: remoteClient.signatures,
      },
      curve: this.tssKeyType,
    };

    const result = (
      await post<{ data: RefreshRemoteTssReturnType }>(
        `${remoteClient.remoteClientUrl}/api/v3/mpc/refresh_tss`,
        { dataRequired },
        {
          headers: {
            Authorization: `Bearer ${remoteClient.remoteClientToken}`,
          },
        }
      )
    ).data;

    this.metadata.updateTSSData({
      tssTag: result.tssTag,
      tssNonce: result.tssNonce,
      tssPolyCommits: result.tssPolyCommits.map((commit) => Point.fromJSON(commit)),
      factorPubs: result.factorPubs.map((pub) => Point.fromJSON(pub)),
      factorEncs: result.factorEncs,
    });
  }

  async remoteAddFactorPub(params: { newFactorPub: Point; newFactorTSSIndex: number; remoteClient: IRemoteClientState }) {
    const { newFactorPub, newFactorTSSIndex, remoteClient } = params;
    const existingFactorPubs = this.metadata.factorPubs[this.tssTag];
    const updatedFactorPubs = existingFactorPubs.concat([newFactorPub]);
    const existingTSSIndexes = existingFactorPubs.map((fb) => this.getFactorEncs(fb).tssIndex);
    const updatedTSSIndexes = existingTSSIndexes.concat([newFactorTSSIndex]);

    await this.remoteRefreshTssShares({
      factorPubs: updatedFactorPubs,
      tssIndices: updatedTSSIndexes,
      remoteClient,
    });
  }

  async remoteDeleteFactorPub(params: { factorPubToDelete: Point; remoteClient: IRemoteClientState }) {
    const { factorPubToDelete, remoteClient } = params;
    const existingFactorPubs = this.metadata.factorPubs[this.tssTag];
    const factorIndex = existingFactorPubs.findIndex((p) => p.x.eq(factorPubToDelete.x));
    if (factorIndex === -1) {
      throw new Error(`factorPub ${factorPubToDelete} does not exist`);
    }
    const updatedFactorPubs = existingFactorPubs.slice();
    updatedFactorPubs.splice(factorIndex, 1);
    const updatedTSSIndexes = updatedFactorPubs.map((fb) => this.getFactorEncs(fb).tssIndex);

    await this.remoteRefreshTssShares({
      factorPubs: updatedFactorPubs,
      tssIndices: updatedTSSIndexes,
      remoteClient,
    });
  }

  async remoteCopyFactorPub(params: { newFactorPub: Point; tssIndex: number; remoteClient: IRemoteClientState }) {
    const { newFactorPub, tssIndex, remoteClient } = params;
    const remoteFactorPub = Point.fromSEC1(secp256k1, remoteClient.remoteFactorPub);
    const factorEnc = this.getFactorEncs(remoteFactorPub);
    const tssCommits = this.getTSSCommits().map((commit) => commit.toPointHex());
    const dataRequired: CopyRemoteTssParams = {
      factorEnc,
      tssCommits,
      factorPub: newFactorPub.toPointHex(),
      curve: this.tssKeyType,
    };

    const result = (
      await post<{ data?: EncryptedMessage }>(
        `${remoteClient.remoteClientUrl}/api/v3/mpc/copy_tss_share`,
        { dataRequired },
        {
          headers: {
            Authorization: `Bearer ${remoteClient.remoteClientToken}`,
          },
        }
      )
    ).data;

    const updatedFactorPubs = this.metadata.factorPubs[this.tssTag].concat([newFactorPub]);
    const factorEncs: { [key: string]: FactorEnc } = JSON.parse(JSON.stringify(this.metadata.factorEncs[this.tssTag]));
    const factorPubID = newFactorPub.x.toString(16, 64);
    factorEncs[factorPubID] = {
      tssIndex,
      type: "direct",
      userEnc: result,
      serverEncs: [],
    };
    this.metadata.updateTSSData({
      tssTag: this.tssTag,
      factorPubs: updatedFactorPubs,
      factorEncs,
    });
  }

  /**
   * Runs the share refresh protocol for the TSS key shares.
   * @param inputShare - The current user secret share.
   * @param inputIndex - The user share index.
   * @param factorPubs - The target factor keys.
   * @param targetIndexes - The target indices to provide new shares for.
   */
  async _refreshTSSShares(
    updateMetadata: boolean,
    inputShare: BN,
    inputIndex: number,
    factorPubs: Point[],
    targetIndexes: number[],
    verifierNameVerifierId: string,
    serverOpts: {
      serverEndpoints: string[];
      serverPubKeys: PointHex[];
      serverThreshold: number;
      selectedServers: number[];
      authSignatures: string[];
    }
  ): Promise<void> {
    if (!this.metadata) throw CoreError.metadataUndefined();
    if (!this.metadata.tssPolyCommits) throw CoreError.default(`tss poly commits obj not found`);
    const tssCommits = this.metadata.tssPolyCommits[this.tssTag];
    if (!tssCommits) throw CoreError.default(`tss commits not found for tssTag ${this.tssTag}`);
    if (tssCommits.length === 0) throw CoreError.default(`tssCommits is empty`);
    const tssPubKeyPoint = tssCommits[0];
    const tssPubKey = pointToHex(tssPubKeyPoint);
    const { serverEndpoints, serverPubKeys, serverThreshold, selectedServers, authSignatures } = serverOpts;

    const rssClient = new RSSClient({
      serverEndpoints,
      serverPubKeys,
      serverThreshold,
      tssPubKey,
      keyType: this._tssKeyType,
    });

    if (!this.metadata.factorPubs) throw CoreError.default(`factorPubs obj not found`);
    if (!factorPubs) throw CoreError.default(`factorPubs not found for tssTag ${this.tssTag}`);
    if (factorPubs.length === 0) throw CoreError.default(`factorPubs is empty`);

    if (!this.metadata.tssNonces) throw CoreError.default(`tssNonces obj not found`);
    const tssNonce: number = this.metadata.tssNonces[this.tssTag] || 0;

    const oldLabel = `${verifierNameVerifierId}\u0015${this.tssTag}\u0016${tssNonce}`;
    const newLabel = `${verifierNameVerifierId}\u0015${this.tssTag}\u0016${tssNonce + 1}`;

    const { pubKey: newTSSServerPub, nodeIndexes } = await this.serviceProvider.getTSSPubKey(this.tssTag, tssNonce + 1);
    let finalSelectedServers = selectedServers;

    if (nodeIndexes?.length > 0) {
      finalSelectedServers = nodeIndexes.slice(0, Math.min(selectedServers.length, nodeIndexes.length));
    }
    const refreshResponses = await rssClient.refresh({
      factorPubs: factorPubs.map((f) => pointToHex(f)),
      targetIndexes,
      oldLabel,
      newLabel,
      sigs: authSignatures,
      dkgNewPub: pointToHex(newTSSServerPub),
      inputShare,
      inputIndex,
      selectedServers: finalSelectedServers,
    });

    const secondCommit = newTSSServerPub.toEllipticPoint(this._tssCurve).add(ecPoint(this._tssCurve, tssPubKey).neg());
    const newTSSCommits = [
      Point.fromJSON(tssPubKey),
      Point.fromJSON({ x: secondCommit.getX().toString(16, 64), y: secondCommit.getY().toString(16, 64) }),
    ];
    const factorEncs: {
      [factorPubID: string]: FactorEnc;
    } = {};
    for (let i = 0; i < refreshResponses.length; i++) {
      const refreshResponse = refreshResponses[i];
      factorEncs[refreshResponse.factorPub.x.padStart(64, "0")] = {
        type: "hierarchical",
        tssIndex: refreshResponse.targetIndex,
        userEnc: refreshResponse.userFactorEnc,
        serverEncs: refreshResponse.serverFactorEncs,
      };
    }

    this.metadata.updateTSSData({
      tssKeyType: this._tssKeyType,
      tssTag: this.tssTag,
      tssNonce: tssNonce + 1,
      tssPolyCommits: newTSSCommits,
      factorPubs,
      factorEncs,
    });
    if (updateMetadata) await this._syncShareMetadata();
  }

  /**
   * Derives the account nonce for the specified account index.
   */
  computeAccountNonce(index?: number): BN {
    if (!index || index === 0) {
      return new BN(0);
    }

    if (this._tssKeyType === KeyType.ed25519) {
      throw new Error("account index not supported with ed25519");
    }

    // generation should occur during tkey.init, fails if accountSalt is absent
    if (!this._accountSalt) {
      throw Error("account salt undefined");
    }
    let accountHash = keccak256(utf8ToBytes(`${index}${this._accountSalt}`));
    if (accountHash.length === 66) accountHash = accountHash.slice(2);
    return new BN(accountHash, "hex").umod(this._tssCurve.n);
  }

  /**
   * Reconstructs the TKey and finalize intialization.
   */
  async reconstructKey(_reconstructKeyMiddleware?: boolean): Promise<ReconstructedKeyResult> {
    const k = await super.reconstructKey(_reconstructKeyMiddleware);

    const accountSalt = (await this.getTKeyStoreItem(TSS_MODULE, "accountSalt")) as IAccountSaltStore;
    if (accountSalt && accountSalt.value) {
      this._accountSalt = accountSalt.value;
    } else {
      const newSalt = generateSalt(this._tssCurve);
      await this._setTKeyStoreItem(TSS_MODULE, {
        id: "accountSalt",
        value: newSalt,
      } as IAccountSaltStore);
      this._accountSalt = newSalt;
      // this is very specific case where exisiting user do not have salt.
      // sync metadata to cloud to ensure salt is stored incase of manual sync mode
      // new user or importKey should not hit this cases
      // NOTE this is not mistake, we force sync for this case
      if (this.manualSync) await this.syncLocalMetadataTransitions();
    }

    return k;
  }

  /**
   * Adds a factor key to the set of authorized keys.
   *
   * `refreshShares` - If this is true, then refresh the shares. If this is
   * false, `newTSSIndex` must be the same as current factor key index.
   */
  public async addFactorPub(args: {
    existingFactorKey: BN;
    newFactorPub: Point;
    newTSSIndex: number;
    selectedServers?: number[];
    authSignatures: string[];
    refreshShares?: boolean;
    updateMetadata?: boolean;
  }) {
    if (!this.metadata) throw CoreError.metadataUndefined("metadata is undefined");
    if (!this.secp256k1Key) throw new Error("Tkey is not reconstructed");
    if (!this.metadata.tssPolyCommits[this.tssTag]) throw new Error(`tss key has not been initialized for tssTag ${this.tssTag}`);
    const { existingFactorKey, newFactorPub, newTSSIndex, selectedServers, authSignatures, refreshShares } = args;

    const { tssShare, tssIndex } = await this.getTSSShare(existingFactorKey);

    if (tssIndex !== newTSSIndex && !refreshShares) {
      throw CoreError.default("newTSSIndex does not match existing tssIndex, set refreshShares to true to refresh shares");
    }

    if (!refreshShares) {
      // Just copy data stored under factor key.
      if (tssIndex !== newTSSIndex) {
        throw CoreError.default("newTSSIndex does not match existing tssIndex, set refreshShares to true to refresh shares");
      }

      const updatedFactorPubs = this.metadata.factorPubs[this.tssTag].concat([newFactorPub]);
      const factorEncs = JSON.parse(JSON.stringify(this.metadata.factorEncs[this.tssTag]));
      const factorPubID = newFactorPub.x.toString(16, 64);
      factorEncs[factorPubID] = {
        tssIndex,
        type: "direct",
        userEnc: await encrypt(newFactorPub.toSEC1(secp256k1, false), new Uint8Array(tssShare.toArrayLike(Buffer, "be", 32))),
        serverEncs: [],
      };
      this.metadata.updateTSSData({
        tssKeyType: this.tssKeyType,
        tssTag: this.tssTag,
        factorPubs: updatedFactorPubs,
        factorEncs,
      });
    } else {
      // Use RSS to create new TSS share and store it under new factor key.
      const existingFactorPubs = this.metadata.factorPubs[this.tssTag];
      const updatedFactorPubs = existingFactorPubs.concat([newFactorPub]);

      const verifierId = this.serviceProvider.getVerifierNameVerifierId();
      const rssNodeDetails = await this._getRssNodeDetails();
      const randomSelectedServers = randomSelection(
        new Array(rssNodeDetails.serverEndpoints.length).fill(null).map((_, i) => i + 1),
        Math.ceil(rssNodeDetails.serverEndpoints.length / 2)
      );

      const finalServer = selectedServers || randomSelectedServers;

      const existingTSSIndexes = existingFactorPubs.map((fb) => this.getFactorEncs(fb).tssIndex);
      const updatedTSSIndexes = existingTSSIndexes.concat([newTSSIndex]);

      // sync metadata by default
      // create a localMetadataTransition if manual sync
      const updateMetadata = args.updateMetadata !== undefined ? args.updateMetadata : true;

      await this._refreshTSSShares(updateMetadata, tssShare, tssIndex, updatedFactorPubs, updatedTSSIndexes, verifierId, {
        ...rssNodeDetails,
        selectedServers: finalServer,
        authSignatures,
      });
    }
  }

  /**
   * Removes a factor key from the set of authorized keys and refreshes the TSS
   * key shares.
   */
  public async deleteFactorPub(args: {
    factorKey: BN;
    deleteFactorPub: Point;
    selectedServers?: number[];
    authSignatures: string[];
    updateMetadata?: boolean;
  }): Promise<void> {
    if (!this.metadata) throw CoreError.metadataUndefined("metadata is undefined");
    if (!this.secp256k1Key) throw new Error("Tkey is not reconstructed");
    if (!this.metadata.tssPolyCommits[this.tssTag]) throw new Error(`tss key has not been initialized for tssTag ${this.tssTag}`);
    const { factorKey, deleteFactorPub, selectedServers, authSignatures } = args;
    const existingFactorPubs = this.metadata.factorPubs[this.tssTag];
    const { tssShare, tssIndex } = await this.getTSSShare(factorKey);

    const found = existingFactorPubs.filter((f) => f.x.eq(deleteFactorPub.x) && f.y.eq(deleteFactorPub.y));
    if (found.length === 0) throw CoreError.default("could not find factorPub to delete");
    if (found.length > 1) throw CoreError.default("found two or more factorPubs that match, error in metadata");
    const updatedFactorPubs = existingFactorPubs.filter((f) => !f.x.eq(deleteFactorPub.x) || !f.y.eq(deleteFactorPub.y));
    this.metadata.updateTSSData({ tssKeyType: this._tssKeyType, tssTag: this.tssTag, factorPubs: updatedFactorPubs });
    const rssNodeDetails = await this._getRssNodeDetails();
    const randomSelectedServers = randomSelection(
      new Array(rssNodeDetails.serverEndpoints.length).fill(null).map((_, i) => i + 1),
      Math.ceil(rssNodeDetails.serverEndpoints.length / 2)
    );

    const finalServer = selectedServers || randomSelectedServers;
    const updatedTSSIndexes = updatedFactorPubs.map((fb) => this.getFactorEncs(fb).tssIndex);

    const updateMetadata = args.updateMetadata !== undefined ? args.updateMetadata : true;

    await this._refreshTSSShares(
      updateMetadata,
      tssShare,
      tssIndex,
      updatedFactorPubs,
      updatedTSSIndexes,
      this.serviceProvider.getVerifierNameVerifierId(),
      {
        ...rssNodeDetails,
        selectedServers: finalServer,
        authSignatures,
      }
    );
  }

  /**
   * Adjusts a TSS key share based on account index and share coefficient.
   */
  protected adjustTssShare(share: BN, accountIndex: number, coefficient: BN): BN {
    const nonce = this.computeAccountNonce(accountIndex);
    return share.mul(coefficient).add(nonce).umod(this._tssCurve.n);
  }

  /**
   * Initializes a new TSS key under the specified factor key and using the
   * provided user share.
   */
  protected async _initializeNewTSSKey(
    tssTag: string,
    deviceTSSShare: BN,
    factorPub: Point,
    deviceTSSIndex?: number
  ): Promise<InitializeNewTSSKeyResult> {
    const ec = this._tssCurve;
    let tss2: BN;
    const _tssIndex = deviceTSSIndex || 2; // TODO: fix
    if (deviceTSSShare) {
      tss2 = deviceTSSShare;
    } else {
      tss2 = this._tssCurve.genKeyPair().getPrivate();
    }
    const { pubKey: tss1Pub } = await this.serviceProvider.getTSSPubKey(tssTag, 0);
    const tss1PubKey = tss1Pub.toEllipticPoint(ec);
    const tss2PubKey = (this._tssCurve.g as EllipticPoint).mul(tss2);

    const L1_0 = getLagrangeCoeffs(ec, [1, _tssIndex], 1, 0);

    const LIndex_0 = getLagrangeCoeffs(ec, [1, _tssIndex], _tssIndex, 0);

    const a0Pub = tss1PubKey.mul(L1_0).add(tss2PubKey.mul(LIndex_0));
    const a1Pub = tss1PubKey.add(a0Pub.neg());

    const tssPolyCommits = [Point.fromElliptic(a0Pub), Point.fromElliptic(a1Pub)];
    const factorPubs = [factorPub];
    const factorEncs: { [factorPubID: string]: FactorEnc } = {};

    for (let i = 0; i < factorPubs.length; i++) {
      const f = factorPubs[i];
      const factorPubID = f.x.toString(16, 64);
      factorEncs[factorPubID] = {
        tssIndex: _tssIndex,
        type: "direct",
        userEnc: await encrypt(f.toSEC1(factorKeyCurve, false), hexToBytes(tss2.toString(16, 64))),
        serverEncs: [],
      };
    }

    return {
      tss2,
      factorEncs,
      factorPubs,
      tssPolyCommits,
    };
  }
}
