import shared from "../../../../test/shared/node.debug.mts";

shared.test!.testTimeout = 0;
shared.test!.maxWorkers = 4;
shared.test!.fileParallelism = true;

export default shared;
