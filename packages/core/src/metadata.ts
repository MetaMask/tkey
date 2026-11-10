import {
  bigIntReplacer,
  decrypt,
  EncryptedMessage,
  FactorEnc,
  getPubKeyPoint,
  IMetadata,
  KeyType,
  Point,
  PolyIDAndShares,
  Polynomial,
  PolynomialID,
  PublicPolynomial,
  PublicPolynomialMap,
  PublicShare,
  PublicSharePolyIDShareIndexMap,
  Share,
  ShareDescriptionMap,
  ShareMap,
  ShareStore,
  StringifiedType,
  toPrivKeyECC,
} from "@tkey/common-types";
import { bytesToHex, bytesToUtf8, hexToBigInt } from "@toruslabs/metadata-helpers";
import stringify from "json-stable-stringify";

import CoreError from "./errors";
import { polyCommitmentEval } from "./lagrangeInterpolatePolynomial";

class Metadata implements IMetadata {
  pubKey: Point;

  publicPolynomials: PublicPolynomialMap;

  publicShares: PublicSharePolyIDShareIndexMap;

  // Tuple of PolyID and array of ShareIndexes
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

  tssKeyTypes?: {
    [tssTag: string]: KeyType;
  };

  tssNonces?: {
    [tssTag: string]: number;
  };

  tssPolyCommits?: {
    [tssTag: string]: Point[];
  };

  factorPubs?: {
    [tssTag: string]: Point[];
  };

  factorEncs?: {
    [tssTag: string]: {
      [factorPubID: string]: FactorEnc;
    };
  };

  constructor(input: Point) {
    this.publicPolynomials = {};
    this.publicShares = {};
    this.generalStore = {};
    this.tkeyStore = {};
    this.scopedStore = {};
    this.pubKey = input;
    this.polyIDList = [];
    this.nonce = 0;
    this.tssKeyTypes = {};
    this.tssPolyCommits = {};
    this.tssNonces = {};
    this.factorPubs = {};
    this.factorEncs = {};
  }

  static fromJSON(value: StringifiedType): Metadata {
    const { pubKey, polyIDList, generalStore, tkeyStore, scopedStore, nonce, tssKeyTypes, tssPolyCommits, tssNonces, factorPubs, factorEncs } = value;
    const point = Point.fromSEC1(pubKey);
    const metadata = new Metadata(point);
    const unserializedPolyIDList: PolyIDAndShares[] = [];

    if (generalStore) metadata.generalStore = generalStore;
    if (tkeyStore) metadata.tkeyStore = tkeyStore;
    if (scopedStore) metadata.scopedStore = scopedStore;
    if (nonce) metadata.nonce = nonce;

    if (tssKeyTypes) {
      metadata.tssKeyTypes = {};
      for (const key in tssKeyTypes) {
        metadata.tssKeyTypes[key] = tssKeyTypes[key];
      }
    }
    if (tssPolyCommits) {
      metadata.tssPolyCommits = {};
      for (const key in tssPolyCommits) {
        const commits = (tssPolyCommits as Record<string, Point[]>)[key];
        if (!commits) throw CoreError.default("missing tss poly commits");
        metadata.tssPolyCommits[key] = commits.map((obj) => Point.fromJSON(obj));
      }
    }
    if (tssNonces) {
      metadata.tssNonces = {};
      for (const key in tssNonces) {
        metadata.tssNonces[key] = tssNonces[key];
      }
    }
    if (factorPubs) {
      metadata.factorPubs = {};
      for (const key in factorPubs) {
        const pubs = (factorPubs as Record<string, Point[]>)[key];
        if (!pubs) throw CoreError.default("missing factor pubs");
        metadata.factorPubs[key] = pubs.map((obj) => Point.fromJSON(obj));
      }
    }
    if (factorEncs) metadata.factorEncs = factorEncs;

    for (let i = 0; i < polyIDList.length; i += 1) {
      const serializedPolyID: string = polyIDList[i];
      const arrPolyID = serializedPolyID.split("|");
      const zeroIndex = arrPolyID.findIndex((v) => v === "0x0");
      const firstHalf = arrPolyID.slice(0, zeroIndex);
      const secondHalf = arrPolyID.slice(zeroIndex + 1, arrPolyID.length);
      // for publicPolynomials
      const pubPolyID = firstHalf.join("|");
      const pointCommitments: Point[] = [];
      firstHalf.forEach((compressedCommitment) => {
        pointCommitments.push(Point.fromCompressedPub(compressedCommitment));
      });
      const publicPolynomial = new PublicPolynomial(pointCommitments);
      metadata.publicPolynomials[pubPolyID] = publicPolynomial;

      // for polyIDList
      unserializedPolyIDList.push([pubPolyID, secondHalf]);
    }

    metadata.polyIDList = unserializedPolyIDList;
    return metadata;
  }

  getShareIndexesForPolynomial(polyID: PolynomialID): Array<string> {
    const matchingPolyIDs = this.polyIDList.filter((tuple) => tuple[0] === polyID);
    if (matchingPolyIDs.length < 1) {
      throw CoreError.default("there is no matching polyID");
    } else if (matchingPolyIDs.length > 1) {
      throw CoreError.default("there is more than one matching polyID");
    }
    const match = matchingPolyIDs[0];
    if (!match) {
      throw CoreError.default("there is no matching polyID");
    }
    return match[1];
  }

  getLatestPublicPolynomial(): PublicPolynomial {
    const latest = this.polyIDList[this.polyIDList.length - 1];
    if (!latest) {
      throw CoreError.default("there is no matching polyID");
    }
    const polynomial = this.publicPolynomials[latest[0]];
    if (!polynomial) {
      throw CoreError.default("there is no matching polyID");
    }
    return polynomial;
  }

  addPublicShare(polynomialID: PolynomialID, publicShare: PublicShare): void {
    if (!(polynomialID in this.publicShares)) {
      this.publicShares[polynomialID] = {};
    }
    const sharesForPolynomial = this.publicShares[polynomialID];
    if (!sharesForPolynomial) {
      throw CoreError.default("there is no matching polyID");
    }
    sharesForPolynomial[publicShare.shareIndex.toString(16)] = publicShare;
  }

  setGeneralStoreDomain(key: string, obj: unknown): void {
    this.generalStore[key] = obj;
  }

  getGeneralStoreDomain(key: string): unknown {
    return this.generalStore[key];
  }

  deleteGeneralStoreDomain(key: string): void {
    delete this.generalStore[key];
  }

  setTkeyStoreDomain(key: string, arr: unknown): void {
    this.tkeyStore[key] = arr;
  }

  getTkeyStoreDomain(key: string): unknown {
    return this.tkeyStore[key];
  }

  // appends shares and public polynomial to metadata.
  // should represent a generation of share or edit of threshold
  addFromPolynomialAndShares(polynomial: Polynomial, shares: Share[] | ShareMap): void {
    const publicPolynomial = polynomial.getPublicPolynomial();
    const polyID = publicPolynomial.getPolynomialID();
    this.publicPolynomials[polyID] = publicPolynomial;

    const shareIndexArr = [];
    if (Array.isArray(shares)) {
      for (let i = 0; i < shares.length; i += 1) {
        const share = shares[i];
        if (!share) throw CoreError.fromCode(1307);
        this.addPublicShare(publicPolynomial.getPolynomialID(), share.getPublicShare());
        shareIndexArr.push(share.shareIndex.toString(16));
      }
    } else {
      for (const k in shares) {
        if (Object.prototype.hasOwnProperty.call(shares, k)) {
          const share = shares[k];
          if (!share) throw CoreError.fromCode(1307);
          this.addPublicShare(publicPolynomial.getPolynomialID(), share.getPublicShare());
          shareIndexArr.push(share.shareIndex.toString(16));
        }
      }
    }
    this.polyIDList.push([polyID, shareIndexArr]);
  }

  setScopedStore(domain: string, data: unknown): void {
    this.scopedStore[domain] = data;
  }

  async getEncryptedShare(shareStore: ShareStore): Promise<ShareStore> {
    const pubShare = shareStore.share.getPublicShare();
    const encryptedShareStore = this.scopedStore.encryptedShares as Record<string, unknown>;
    if (!encryptedShareStore) {
      throw CoreError.encryptedShareStoreUnavailable(`${shareStore}`);
    }
    const encryptedShare = encryptedShareStore[pubShare.shareCommitment.x.toString(16)];
    if (!encryptedShare) {
      throw CoreError.encryptedShareStoreUnavailable(`${shareStore}`);
    }
    const rawDecrypted = await decrypt(toPrivKeyECC(shareStore.share.share), encryptedShare as EncryptedMessage);
    return ShareStore.fromJSON(JSON.parse(bytesToUtf8(rawDecrypted)));
  }

  getShareDescription(): ShareDescriptionMap {
    return this.getGeneralStoreDomain("shareDescriptions") as ShareDescriptionMap;
  }

  addShareDescription(shareIndex: string, description: string): void {
    const currentSD = (this.getGeneralStoreDomain("shareDescriptions") || {}) as Record<string, string[]>;
    if (currentSD[shareIndex]) {
      currentSD[shareIndex].push(description);
    } else {
      currentSD[shareIndex] = [description];
    }
    this.setGeneralStoreDomain("shareDescriptions", currentSD);
  }

  deleteShareDescription(shareIndex: string, description: string): void {
    const currentSD = this.getGeneralStoreDomain("shareDescriptions") as Record<string, string[]>;
    const descriptions = currentSD[shareIndex];
    if (!descriptions) {
      throw CoreError.default(`No share description found for the given shareIndex: ${shareIndex} 
        and description: ${description}`);
    }
    const index = descriptions.indexOf(description);
    if (index > -1) {
      descriptions.splice(index, 1);
    } else {
      throw CoreError.default(`No share description found for the given shareIndex: ${shareIndex} 
        and description: ${description}`);
    }
  }

  updateShareDescription(shareIndex: string, oldDescription: string, newDescription: string): void {
    const currentSD = this.getGeneralStoreDomain("shareDescriptions") as Record<string, string[]>;
    const descriptions = currentSD[shareIndex];
    if (!descriptions) {
      throw CoreError.default(`No share description found for the given shareIndex:
        ${shareIndex} and description: ${oldDescription}`);
    }
    const index = descriptions.indexOf(oldDescription);
    if (index > -1) {
      descriptions[index] = newDescription;
    } else {
      throw CoreError.default(`No share description found for the given shareIndex:
        ${shareIndex} and description: ${oldDescription}`);
    }
  }

  shareToShareStore(share: bigint): ShareStore {
    const pubkey = getPubKeyPoint(share);

    for (let i = this.polyIDList.length - 1; i >= 0; i -= 1) {
      const polyEntry = this.polyIDList[i];
      if (!polyEntry) throw CoreError.default("there is no matching polyID");
      const el = polyEntry[0];
      const indexes = polyEntry[1];

      for (let t = 0; t < indexes.length; t += 1) {
        const shareIndex = indexes[t];
        if (shareIndex === undefined) throw CoreError.fromCode(1307);
        // find pubshare in cache if its there
        let pubShare: PublicShare | undefined;
        const cachedShares = this.publicShares[el];
        if (cachedShares) {
          const cached = cachedShares[shareIndex];
          if (cached) {
            pubShare = cached;
          }
        }

        // if not reconstruct
        if (!pubShare) {
          const shareIndexBigInt = hexToBigInt(shareIndex);
          const polynomial = this.publicPolynomials[el];
          if (!polynomial) throw CoreError.default("there is no matching polyID");
          pubShare = new PublicShare(shareIndexBigInt, polyCommitmentEval(polynomial.polynomialCommitments, shareIndexBigInt));
        }
        if (pubShare.shareCommitment.x === pubkey.x && pubShare.shareCommitment.y === pubkey.y) {
          const tempShare = new Share(pubShare.shareIndex, share);
          return new ShareStore(tempShare, el);
        }
      }
    }
    throw CoreError.fromCode(1307);
  }

  clone(): Metadata {
    const serialized = stringify(this, { replacer: bigIntReplacer });
    if (serialized === undefined) throw CoreError.default("Unable to serialize metadata");
    return Metadata.fromJSON(JSON.parse(serialized));
  }

  toJSON(): StringifiedType {
    // squash data to serialized polyID according to spec
    const serializedPolyIDList = [];
    for (let i = 0; i < this.polyIDList.length; i += 1) {
      const polyEntry = this.polyIDList[i];
      if (!polyEntry) throw CoreError.default("there is no matching polyID");
      const polyID = polyEntry[0];
      const shareIndexes = polyEntry[1];
      const sortedShareIndexes = shareIndexes.sort((a: string, b: string) => {
        const aBig = hexToBigInt(a);
        const bBig = hexToBigInt(b);
        return aBig < bBig ? -1 : aBig > bBig ? 1 : 0;
      });
      const serializedPolyID = polyID
        .split(`|`)
        .concat("0x0")
        .concat(...sortedShareIndexes)
        .join("|");
      serializedPolyIDList.push(serializedPolyID);
    }

    return {
      pubKey: bytesToHex(this.pubKey.toSEC1(true)),
      polyIDList: serializedPolyIDList,
      scopedStore: this.scopedStore,
      generalStore: this.generalStore,
      tkeyStore: this.tkeyStore,
      nonce: this.nonce,
      ...(this.tssKeyTypes && { tssKeyTypes: this.tssKeyTypes }),
      ...(this.tssNonces && { tssNonces: this.tssNonces }),
      ...(this.tssPolyCommits && { tssPolyCommits: this.tssPolyCommits }),
      ...(this.factorPubs && { factorPubs: this.factorPubs }),
      ...(this.factorEncs && { factorEncs: this.factorEncs }),
    };
  }

  /**
   * Updates the TSS metadata for the given tag.
   */
  updateTSSData(tssData: {
    tssTag: string;
    tssKeyType?: KeyType;
    tssNonce?: number;
    tssPolyCommits?: Point[];
    factorPubs?: Point[];
    factorEncs?: {
      [factorPubID: string]: FactorEnc;
    };
  }): void {
    const { tssKeyType, tssTag, tssNonce, tssPolyCommits, factorPubs, factorEncs } = tssData;
    if (tssKeyType) {
      this.tssKeyTypes ??= {};
      this.tssKeyTypes[tssTag] = tssKeyType;
    }
    if (tssNonce !== undefined) {
      this.tssNonces ??= {};
      this.tssNonces[tssTag] = tssNonce;
    }
    if (tssPolyCommits) {
      this.tssPolyCommits ??= {};
      this.tssPolyCommits[tssTag] = tssPolyCommits;
    }
    if (factorPubs) {
      this.factorPubs ??= {};
      this.factorPubs[tssTag] = factorPubs;
    }
    if (factorEncs) {
      this.factorEncs ??= {};
      this.factorEncs[tssTag] = factorEncs;
    }
  }
}

export default Metadata;
