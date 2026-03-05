import { ShareTransferStorePointerArgs } from "@tkey/common-types";
import { hexToBigInt } from "@toruslabs/metadata-helpers";

class ShareTransferStorePointer {
  pointer: bigint;

  constructor({ pointer }: ShareTransferStorePointerArgs) {
    this.pointer = typeof pointer === "bigint" ? pointer : hexToBigInt(pointer);
  }
}
export default ShareTransferStorePointer;
