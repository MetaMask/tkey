import { bytesToHex } from "@noble/curves/utils.js";
import { ServiceProviderBase } from "@tkey/service-provider-base";
import { generatePrivate } from "@toruslabs/eccrypto";
import { describe, it } from "vitest";

import { getMetadataUrl, initStorageLayer } from "./helpers";
import { sharedTestCases } from "./shared";

const runFull = process.env.TKEY_FULL === "1";
const MANUAL_SYNC = false;
const metadataURL = getMetadataUrl();
const PRIVATE_KEY = bytesToHex(generatePrivate());
const defaultSP = new ServiceProviderBase({ postboxKey: PRIVATE_KEY });
const defaultSL = initStorageLayer({ hostUrl: metadataURL });

describe(`BaseServiceProvider with manualSync: ${MANUAL_SYNC}`, function () {
  if (runFull) {
    sharedTestCases(MANUAL_SYNC, defaultSP, defaultSL);
  } else {
    it.skip("run with TKEY_FULL=1 for full suite", () => {});
  }
});
