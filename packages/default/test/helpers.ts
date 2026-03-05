import { ServiceProviderBase } from "@tkey/service-provider-base";
import { TorusServiceProvider } from "@tkey/service-provider-torus";
import { MockStorageLayer, TorusStorageLayer } from "@tkey/storage-layer-torus";
import { generatePrivate } from "@toruslabs/eccrypto";
import { bytesToHex } from "@toruslabs/metadata-helpers";

const mocked = process.env.MOCKED ?? "false";

export const isMocked = mocked === "true";

export function getMetadataUrl(): string {
  return process.env.METADATA ?? "http://localhost:5051";
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
