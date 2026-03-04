import { describe, it } from "vitest";
import { bytesToHex } from "@noble/curves/utils.js";
import { TorusServiceProvider } from "@tkey/service-provider-torus";
import { generatePrivate } from "@toruslabs/eccrypto";

import { getMetadataUrl, initStorageLayer } from "./helpers";
import { sharedTestCases } from "./shared";

const runFull = process.env.TKEY_FULL === "1";
const metadataURL = getMetadataUrl();

const PRIVATE_KEY = bytesToHex(generatePrivate());
const torusSP = new TorusServiceProvider({
  postboxKey: PRIVATE_KEY,
  customAuthArgs: {
    baseUrl: "http://localhost:3000",
    web3AuthClientId: "test",
    network: "mainnet",
  },
});

const torusSL = initStorageLayer({ hostUrl: metadataURL });

const MANUAL_SYNC = false;
describe(`TorusServiceProvider with manualSync: ${MANUAL_SYNC}`, function () {
  if (runFull) {
    sharedTestCases(MANUAL_SYNC, torusSP, torusSL);
  } else {
    it.skip("run with TKEY_FULL=1 for full suite", () => {});
  }
});
