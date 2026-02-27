import { ISerializable, PolynomialID, PublicShare, SecurityQuestionStoreArgs, StringifiedType } from "@tkey/common-types";

class SecurityQuestionStore implements ISerializable {
  nonce: bigint;

  shareIndex: bigint;

  sqPublicShare: PublicShare;

  polynomialID: PolynomialID;

  questions: string;

  constructor({ nonce, shareIndex, sqPublicShare, polynomialID, questions }: SecurityQuestionStoreArgs) {
    this.nonce = typeof nonce === "bigint" ? nonce : BigInt(`0x${nonce}`);
    this.shareIndex = typeof shareIndex === "bigint" ? shareIndex : BigInt(`0x${shareIndex}`);
    this.sqPublicShare = sqPublicShare instanceof PublicShare ? sqPublicShare : PublicShare.fromJSON(sqPublicShare);
    this.polynomialID = polynomialID;
    this.questions = questions;
  }

  static fromJSON(value: StringifiedType): SecurityQuestionStore {
    const { nonce, shareIndex, sqPublicShare, polynomialID, questions } = value;
    return new SecurityQuestionStore({
      nonce,
      shareIndex,
      sqPublicShare: PublicShare.fromJSON(sqPublicShare),
      polynomialID,
      questions,
    });
  }

  toJSON(): StringifiedType {
    return {
      nonce: this.nonce.toString(16),
      shareIndex: this.shareIndex.toString(16),
      sqPublicShare: this.sqPublicShare,
      polynomialID: this.polynomialID,
      questions: this.questions,
    };
  }
}
export default SecurityQuestionStore;
