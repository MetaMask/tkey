import { describe } from "vitest";
import { ServiceProviderBase } from "@tkey/service-provider-base";
import { bytesToHex } from "@noble/curves/utils.js";
import { generatePrivate } from "@toruslabs/eccrypto";

import { getMetadataUrl, initStorageLayer } from "./helpers";
import { sharedTestCases } from "./shared";

const MANUAL_SYNC = true;
const metadataURL = getMetadataUrl();

const PRIVATE_KEY = bytesToHex(generatePrivate());
const defaultSP = new ServiceProviderBase({ postboxKey: PRIVATE_KEY });
const defaultSL = initStorageLayer({ hostUrl: metadataURL });

describe(`BaseServiceProvider with manualSync: ${MANUAL_SYNC}`, function () {
  sharedTestCases(MANUAL_SYNC, defaultSP, defaultSL);
});
