import { BufferObj, EncryptedMessage, ShareRequestArgs } from "@tkey/common-types";

class ShareRequest {
  encPubKey: Uint8Array;

  encShareInTransit: EncryptedMessage;

  availableShareIndexes: Array<string>;

  userAgent: string;

  customInfo: string;

  userIp: string;

  timestamp: number;

  constructor({ encPubKey, encShareInTransit, availableShareIndexes, userAgent, userIp, timestamp }: ShareRequestArgs) {
    const testEncPubKey = encPubKey as BufferObj;
    if (testEncPubKey.type === "Buffer") {
      this.encPubKey = new Uint8Array(testEncPubKey.data);
    } else {
      this.encPubKey = encPubKey as unknown as Uint8Array;
    }
    this.availableShareIndexes = availableShareIndexes;
    this.encShareInTransit = encShareInTransit;
    this.userAgent = userAgent;
    this.userIp = userIp;
    this.timestamp = timestamp;
  }
}

export default ShareRequest;
