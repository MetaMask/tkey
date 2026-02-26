import { ISerializable, StringifiedType } from "../baseTypes/commonTypes";
import Point, { hexToBigInt } from "./Point";

class PublicShare implements ISerializable {
  shareCommitment: Point;

  shareIndex: bigint;

  constructor(shareIndex: bigint, shareCommitment: Point) {
    this.shareCommitment = new Point(shareCommitment.x, shareCommitment.y);
    this.shareIndex = shareIndex;
  }

  static fromJSON(value: StringifiedType): PublicShare {
    const { shareCommitment, shareIndex } = value;
    return new PublicShare(hexToBigInt(shareIndex), Point.fromJSON(shareCommitment));
  }

  toJSON(): StringifiedType {
    return {
      shareCommitment: this.shareCommitment,
      shareIndex: this.shareIndex.toString(16),
    };
  }
}

export default PublicShare;

type PublicShareShareIndexMap = {
  [shareIndex: string]: PublicShare;
};

// @flow
export type PublicSharePolyIDShareIndexMap = {
  [polynomialID: string]: PublicShareShareIndexMap;
};
