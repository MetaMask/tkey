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
    if (encPubKey instanceof Uint8Array) {
      this.encPubKey = encPubKey;
    } else if ((encPubKey as BufferObj).type === "Buffer") {
      this.encPubKey = new Uint8Array((encPubKey as BufferObj).data);
    } else {
      this.encPubKey = Uint8Array.from(Object.values(encPubKey as ArrayLike<number>));
    }
    this.availableShareIndexes = availableShareIndexes;
    this.encShareInTransit = encShareInTransit;
    this.userAgent = userAgent;
    this.userIp = userIp;
    this.timestamp = timestamp;
  }
}

export default ShareRequest;
