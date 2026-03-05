import {
  GenerateNewShareResult,
  IModule,
  isEmptyObject,
  ISQAnswerStore,
  ITKeyApi,
  SecurityQuestionStoreArgs,
  Share,
  ShareStore,
  ShareStoreMap,
} from "@tkey/common-types";
import { bytesToNumberBE, keccak256Bytes, mod, secp256k1, utf8ToBytes } from "@toruslabs/metadata-helpers";

import SecurityQuestionsError from "./errors";
import SecurityQuestionStore from "./SecurityQuestionStore";

function answerToUserInputHashBigInt(answerString: string): bigint {
  const answerHashBytes = keccak256Bytes(utf8ToBytes(answerString));
  return bytesToNumberBE(answerHashBytes);
}

export const SECURITY_QUESTIONS_MODULE_NAME = "securityQuestions";
const TKEYSTORE_ID = "answer";

class SecurityQuestionsModule implements IModule {
  moduleName: string;

  tbSDK: ITKeyApi;

  saveAnswers: boolean;

  constructor(saveAnswers?: boolean) {
    this.saveAnswers = saveAnswers;
    this.moduleName = SECURITY_QUESTIONS_MODULE_NAME;
  }

  static refreshSecurityQuestionsMiddleware(generalStore: unknown, oldShareStores: ShareStoreMap, newShareStores: ShareStoreMap): unknown {
    if (generalStore === undefined || isEmptyObject(generalStore)) {
      return generalStore;
    }
    const sqStore = new SecurityQuestionStore(generalStore as SecurityQuestionStoreArgs);
    const sqIndex = sqStore.shareIndex.toString(16);

    // Assumption: If sqIndex doesn't exist, it must have been explicitly deleted.
    if (oldShareStores[sqIndex] && newShareStores[sqIndex]) {
      const sqAnswer = oldShareStores[sqIndex].share.share - sqStore.nonce;
      const newNonce = mod(newShareStores[sqIndex].share.share - sqAnswer, secp256k1.Point.CURVE().n);

      return new SecurityQuestionStore({
        nonce: newNonce,
        polynomialID: newShareStores[Object.keys(newShareStores)[0]].polynomialID,
        sqPublicShare: newShareStores[sqIndex].share.getPublicShare(),
        shareIndex: sqStore.shareIndex,
        questions: sqStore.questions,
      });
    }
    return undefined;
  }

  setModuleReferences(tbSDK: ITKeyApi): void {
    this.tbSDK = tbSDK;
    this.tbSDK._addRefreshMiddleware(this.moduleName, SecurityQuestionsModule.refreshSecurityQuestionsMiddleware);
  }

  async initialize(): Promise<void> {}

  async generateNewShareWithSecurityQuestions(answerString: string, questions: string): Promise<GenerateNewShareResult> {
    const metadata = this.tbSDK.getMetadata();
    const rawSqStore = metadata.getGeneralStoreDomain(this.moduleName);
    if (rawSqStore) throw SecurityQuestionsError.unableToReplace();
    const newSharesDetails = await this.tbSDK.generateNewShare();
    const newShareStore = newSharesDetails.newShareStores[newSharesDetails.newShareIndex.toString(16)];
    const userInputHash = answerToUserInputHashBigInt(answerString);
    const nonce = mod(newShareStore.share.share - userInputHash, secp256k1.Point.CURVE().n);
    const sqStore = new SecurityQuestionStore({
      nonce,
      questions,
      sqPublicShare: newShareStore.share.getPublicShare(),
      shareIndex: newShareStore.share.shareIndex,
      polynomialID: newShareStore.polynomialID,
    });
    metadata.setGeneralStoreDomain(this.moduleName, sqStore);

    await this.tbSDK.addShareDescription(
      newSharesDetails.newShareIndex.toString(16),
      JSON.stringify({ module: this.moduleName, questions, dateAdded: Date.now() }),
      false // READ TODO1 (don't sync metadata)
    );
    // set on tkey store
    await this.saveAnswerOnTkeyStore(answerString);
    await this.tbSDK._syncShareMetadata();
    return newSharesDetails;
  }

  getSecurityQuestions(): string {
    const metadata = this.tbSDK.getMetadata();
    const sqStore = new SecurityQuestionStore(metadata.getGeneralStoreDomain(this.moduleName) as SecurityQuestionStoreArgs);
    return sqStore.questions;
  }

  async inputShareFromSecurityQuestions(answerString: string): Promise<void> {
    const metadata = this.tbSDK.getMetadata();
    const rawSqStore = metadata.getGeneralStoreDomain(this.moduleName);
    if (!rawSqStore) throw SecurityQuestionsError.unavailable();

    const sqStore = new SecurityQuestionStore(rawSqStore as SecurityQuestionStoreArgs);
    const userInputHash = answerToUserInputHashBigInt(answerString);
    const share = mod(sqStore.nonce + userInputHash, secp256k1.Point.CURVE().n);
    const shareStore = new ShareStore(new Share(sqStore.shareIndex, share), sqStore.polynomialID);
    // validate if share is correct
    const derivedPublicShare = shareStore.share.getPublicShare();
    if (derivedPublicShare.shareCommitment.x !== sqStore.sqPublicShare.shareCommitment.x) {
      throw SecurityQuestionsError.incorrectAnswer();
    }

    const latestShareDetails = await this.tbSDK.catchupToLatestShare({ shareStore, includeLocalMetadataTransitions: true });
    // TODO: update share nonce on all metadata. would be cleaner in long term?
    // if (shareStore.polynomialID !== latestShareDetails.latestShare.polynomialID) this.storeDeviceShare(latestShareDetails.latestShare);
    this.tbSDK.inputShareStore(latestShareDetails.latestShare);
  }

  async changeSecurityQuestionAndAnswer(newAnswerString: string, newQuestions: string): Promise<void> {
    const metadata = this.tbSDK.getMetadata();
    const rawSqStore = metadata.getGeneralStoreDomain(this.moduleName);
    if (!rawSqStore) throw SecurityQuestionsError.unavailable();

    const sqStore = new SecurityQuestionStore(rawSqStore as SecurityQuestionStoreArgs);

    const userInputHash = answerToUserInputHashBigInt(newAnswerString);
    const sqShare = this.tbSDK.outputShareStore(sqStore.shareIndex);
    const nonce = mod(sqShare.share.share - userInputHash, secp256k1.Point.CURVE().n);

    const newSqStore = new SecurityQuestionStore({
      nonce,
      polynomialID: sqStore.polynomialID,
      sqPublicShare: sqStore.sqPublicShare,
      shareIndex: sqStore.shareIndex,
      questions: newQuestions,
    });
    metadata.setGeneralStoreDomain(this.moduleName, newSqStore);
    await this.saveAnswerOnTkeyStore(newAnswerString);
    await this.tbSDK._syncShareMetadata();
  }

  async saveAnswerOnTkeyStore(answerString: string): Promise<void> {
    if (!this.saveAnswers) return;

    const answerStore: ISQAnswerStore = {
      answer: answerString,
      id: TKEYSTORE_ID,
    };
    await this.tbSDK._setTKeyStoreItem(this.moduleName, answerStore, false);
  }

  async getAnswer(): Promise<string> {
    //  TODO: TODO1 edit setTKeyStoreItem to not sync all the time.
    if (this.saveAnswers) {
      const answerStore = (await this.tbSDK.getTKeyStoreItem(this.moduleName, TKEYSTORE_ID)) as ISQAnswerStore;
      return answerStore.answer;
    }
    throw SecurityQuestionsError.noPasswordSaved();
  }
}

export default SecurityQuestionsModule;
