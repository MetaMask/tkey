import { ShareTransferStorePointerArgs } from "@tkey/common-types";

class ShareTransferStorePointer {
  pointer: bigint;

  constructor({ pointer }: ShareTransferStorePointerArgs) {
    this.pointer = typeof pointer === "bigint" ? pointer : BigInt(`0x${pointer}`);
  }
}
export default ShareTransferStorePointer;
