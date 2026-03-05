import { hexToBigInt } from "@toruslabs/metadata-helpers";

import { ISerializable, StringifiedType } from "../baseTypes/commonTypes";
import { getPubKeyPoint } from "./keyUtils";
import PublicShare from "./PublicShare";

class Share implements ISerializable {
  share: bigint;

  shareIndex: bigint;

  constructor(shareIndex: bigint, share: bigint) {
    this.share = share;
    this.shareIndex = shareIndex;
  }

  static fromJSON(value: StringifiedType): Share {
    const { share, shareIndex } = value;
    return new Share(hexToBigInt(shareIndex), hexToBigInt(share));
  }

  getPublicShare(): PublicShare {
    return new PublicShare(this.shareIndex, getPubKeyPoint(this.share));
  }

  toJSON(): StringifiedType {
    return {
      share: this.share.toString(16),
      shareIndex: this.shareIndex.toString(16),
    };
  }
}

export default Share;
