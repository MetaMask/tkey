import { TorusServiceProvider } from "@tkey/service-provider-torus";
import { bytesToHex } from "@noble/curves/utils.js";
import { generatePrivate } from "@toruslabs/eccrypto";

import { getMetadataUrl, initStorageLayer } from "./helpers";
import { sharedTestCases } from "./shared";

const metadataURL = getMetadataUrl();

const PRIVATE_KEY = bytesToHex(generatePrivate());
const torusSP = new TorusServiceProvider({
  postboxKey: PRIVATE_KEY,
  customAuthArgs: {
    // this url has no effect as postbox key is passed
    // passing it just to satisfy direct auth checks.
    baseUrl: "http://localhost:3000",
    web3AuthClientId: "test",
    network: "mainnet",
  },
});

const torusSL = initStorageLayer({ hostUrl: metadataURL });

const MANUAL_SYNC = false;
describe(`TorusServiceProvider with manualSync: ${MANUAL_SYNC}`, function () {
  // eslint-disable-next-line mocha/no-setup-in-describe
  sharedTestCases(MANUAL_SYNC, torusSP, torusSL);
});
