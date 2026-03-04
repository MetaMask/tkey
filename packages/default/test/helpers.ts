import { ServiceProviderBase } from "@tkey/service-provider-base";
import { TorusServiceProvider } from "@tkey/service-provider-torus";
import { MockStorageLayer, TorusStorageLayer } from "@tkey/storage-layer-torus";
import { generatePrivate } from "@toruslabs/eccrypto";
import { bytesToHex } from "@toruslabs/metadata-helpers";

declare global {
  // eslint-disable-next-line no-var
  var __karma__: { config: { args: string[] } } | undefined;
}

let mocked: string;
const isNode = typeof process !== "undefined" && process.release;
if (!isNode && typeof globalThis.__karma__ !== "undefined") {
  [mocked] = globalThis.__karma__.config.args;
} else {
  mocked = process.env.MOCKED ?? "false";
}

export const isMocked = mocked === "true";

export function getMetadataUrl(): string {
  let metadataURL = process.env.METADATA ?? "http://localhost:5051";
  if (!isNode && typeof globalThis.__karma__ !== "undefined") {
    [, metadataURL] = globalThis.__karma__.config.args;
  }
  return metadataURL;
}

export function initStorageLayer(extraParams: { hostUrl: string }) {
  return mocked === "true" ? new MockStorageLayer() : new TorusStorageLayer(extraParams);
}

export function getServiceProvider(params: {
  type: string;
  privKeyBN?: bigint;
  isEmptyProvider?: boolean;
}): TorusServiceProvider | ServiceProviderBase {
  const { type, privKeyBN, isEmptyProvider } = params;
  const PRIVATE_KEY = privKeyBN ? privKeyBN.toString(16) : bytesToHex(generatePrivate());
  if (type === "TorusServiceProvider") {
    return new TorusServiceProvider({
      postboxKey: isEmptyProvider ? null : PRIVATE_KEY,
      customAuthArgs: {
        baseUrl: "http://localhost:3000",
        web3AuthClientId: "test",
        network: "mainnet",
      },
    });
  }
  return new ServiceProviderBase({ postboxKey: isEmptyProvider ? null : PRIVATE_KEY });
}
