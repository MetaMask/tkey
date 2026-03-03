import { ISerializable, PolynomialID, StringifiedType } from "../baseTypes/commonTypes";
import Share from "./Share";

class ShareStore implements ISerializable {
  share: Share;

  polynomialID: PolynomialID;

  constructor(share: Share, polynomialID: PolynomialID) {
    this.share = share;
    this.polynomialID = polynomialID;
  }

  static fromJSON(value: StringifiedType): ShareStore {
    const { share, polynomialID } = value;
    return new ShareStore(Share.fromJSON(share), polynomialID);
  }

  toJSON(): StringifiedType {
    return {
      share: this.share,
      polynomialID: this.polynomialID.toString(),
    };
  }
}

export type EncryptedShareStore = {
  [shareCommitment: string]: ShareStore;
};

export type ShareStoreMap = {
  [shareIndex: string]: ShareStore;
};

export type ShareStorePolyIDShareIndexMap = {
  [polynomialID: string]: ShareStoreMap;
};

export default ShareStore;
