import {
  GenerateNewShareResult,
  IModule,
  isEmptyObject,
  ISQAnswerStore,
  ITKeyApi,
  secp256k1,
  SecurityQuestionStoreArgs,
  Share,
  ShareStore,
  ShareStoreMap,
} from "@tkey/common-types";
import { utf8ToBytes } from "@toruslabs/metadata-helpers";
import BN from "bn.js";
import { keccak256 } from "ethereum-cryptography/keccak";

import SecurityQuestionsError from "./errors";
import SecurityQuestionStore from "./SecurityQuestionStore";

function answerToUserInputHashBN(answerString: string): BN {
  return new BN(keccak256(utf8ToBytes(answerString)));
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
    const sqIndex = sqStore.shareIndex.toString("hex");

    // Assumption: If sqIndex doesn't exist, it must have been explicitly deleted.
    if (oldShareStores[sqIndex] && newShareStores[sqIndex]) {
      const sqAnswer = oldShareStores[sqIndex].share.share.sub(sqStore.nonce);
      let newNonce = newShareStores[sqIndex].share.share.sub(sqAnswer);
      newNonce = newNonce.umod(secp256k1.curve.n);

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
    const newShareStore = newSharesDetails.newShareStores[newSharesDetails.newShareIndex.toString("hex")];
    const userInputHash = answerToUserInputHashBN(answerString);
    let nonce = newShareStore.share.share.sub(userInputHash);
    nonce = nonce.umod(secp256k1.curve.n);
    const sqStore = new SecurityQuestionStore({
      nonce,
      questions,
      sqPublicShare: newShareStore.share.getPublicShare(),
      shareIndex: newShareStore.share.shareIndex,
      polynomialID: newShareStore.polynomialID,
    });
    metadata.setGeneralStoreDomain(this.moduleName, sqStore);

    await this.tbSDK.addShareDescription(
      newSharesDetails.newShareIndex.toString("hex"),
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
    const userInputHash = answerToUserInputHashBN(answerString);
    let share = sqStore.nonce.add(userInputHash);
    share = share.umod(secp256k1.curve.n);
    const shareStore = new ShareStore(new Share(sqStore.shareIndex, share), sqStore.polynomialID);
    // validate if share is correct
    const derivedPublicShare = shareStore.share.getPublicShare();
    if (derivedPublicShare.shareCommitment.x.cmp(sqStore.sqPublicShare.shareCommitment.x) !== 0) {
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

    const userInputHash = answerToUserInputHashBN(newAnswerString);
    const sqShare = this.tbSDK.outputShareStore(sqStore.shareIndex);
    let nonce = sqShare.share.share.sub(userInputHash);
    nonce = nonce.umod(secp256k1.curve.n);

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
