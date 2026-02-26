import { hexToBytes } from "@toruslabs/metadata-helpers";
import { deepStrictEqual } from "assert";
import BN from "bn.js";

import ServiceProviderBase from "../src/ServiceProviderBase";

const PRIVATE_KEY = "e70fb5f5970b363879bc36f54d4fc0ad77863bfd059881159251f50f48863acf";

describe("ServiceProvider", function () {
  it("#should encrypt and decrypt correctly", async function () {
    const privKey = PRIVATE_KEY;
    const tmp = new BN(123);
    const message = hexToBytes(tmp.toString("hex", 15));
    const tsp = new ServiceProviderBase({ postboxKey: privKey });
    const encDeets = await tsp.encrypt(message);
    const result = await tsp.decrypt(encDeets);
    deepStrictEqual(result, message, "encrypted and decrypted message should be equal");
  });

  it("#should encrypt and decrypt correctly messages > 15", async function () {
    const privKey = PRIVATE_KEY;
    const tmp = new BN(123);
    const message = hexToBytes(tmp.toString("hex", 16));
    const tsp = new ServiceProviderBase({ postboxKey: privKey });
    const encDeets = await tsp.encrypt(message);
    const result = await tsp.decrypt(encDeets);
    deepStrictEqual(result, message, "encrypted and decrypted message should be equal");
  });
});
