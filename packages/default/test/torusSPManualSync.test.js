import { TorusServiceProvider } from "@tkey/service-provider-torus";
import { bytesToHex } from "@noble/curves/utils.js";
import { generatePrivate } from "@toruslabs/eccrypto";

import { getMetadataUrl, initStorageLayer } from "./helpers";
import { sharedTestCases } from "./shared";

const PRIVATE_KEY = bytesToHex(generatePrivate());
const torusSp = new TorusServiceProvider({
  postboxKey: PRIVATE_KEY,
  customAuthArgs: {
    baseUrl: "http://localhost:3000",
    web3AuthClientId: "test",
    network: "mainnet",
  },
});
const metadataURL = getMetadataUrl();

const torusSL = initStorageLayer({ hostUrl: metadataURL });

const MANUAL_SYNC = true;
describe(`TorusServiceProvider with manualSync: ${MANUAL_SYNC}`, function () {
  // eslint-disable-next-line mocha/no-setup-in-describe
  sharedTestCases(MANUAL_SYNC, torusSp, torusSL);
});
