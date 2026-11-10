import { TKey as ThresholdKey } from "@tkey/core";
import { ServiceProviderBase } from "@tkey/service-provider-base";
import { MockStorageLayer, TorusStorageLayer } from "@tkey/storage-layer-torus";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import WebStorageModule, { WEB_STORAGE_MODULE_NAME } from "../src/WebStorageModule";

function initStorageLayer(mocked: string, extraParams: { hostUrl: string }) {
  return mocked === "true" ? new MockStorageLayer() : new TorusStorageLayer(extraParams);
}

const mocked = process.env.MOCKED || "false";
const metadataURL = process.env.METADATA || "http://localhost:5051";

const PRIVATE_KEY = "f70fb5f5970b363879bc36f54d4fc0ad77863bfd059881159251f50f48863acc";
const defaultSP = new ServiceProviderBase({ postboxKey: PRIVATE_KEY });
const defaultSL = initStorageLayer(mocked, { hostUrl: metadataURL });

/** Test-only: call private _initializeNewKey (bypass visibility for setup). */
function initializeNewKey(t: InstanceType<typeof ThresholdKey>, opts?: { initializeModules?: boolean }) {
  return (t as unknown as { _initializeNewKey(opts?: any): Promise<unknown> })._initializeNewKey(opts);
}

const manualSyncModes = [true, false];
manualSyncModes.forEach((mode) => {
  describe("web storage", function () {
    let tb: InstanceType<typeof ThresholdKey>;
    let tb2: InstanceType<typeof ThresholdKey>;

    beforeEach(async function () {
      tb = new ThresholdKey({
        serviceProvider: defaultSP,
        storageLayer: defaultSL,
        modules: { [WEB_STORAGE_MODULE_NAME]: new WebStorageModule() },
        manualSync: mode,
      });
      tb2 = new ThresholdKey({
        serviceProvider: defaultSP,
        storageLayer: defaultSL,
        modules: { [WEB_STORAGE_MODULE_NAME]: new WebStorageModule() },
        manualSync: mode,
      });
    });

    it(`#should be able to input share from web storage, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const reconstructedKey = await tb.reconstructKey();
      await tb2.initialize();
      await (tb2.modules[WEB_STORAGE_MODULE_NAME] as WebStorageModule).inputShareFromWebStorage();
      const secondKey = await tb2.reconstructKey();
      expect(secondKey).toStrictEqual(reconstructedKey);
    });

    it(`#should be able to input share from web storage after reconstruction, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });
      const reconstructedKey = await tb.reconstructKey();
      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      await tb.reconstructKey();
      await tb2.initialize();
      await (tb2.modules[WEB_STORAGE_MODULE_NAME] as WebStorageModule).inputShareFromWebStorage();
      const secondKey = await tb2.reconstructKey();
      expect(reconstructedKey.secp256k1Key.toString(16)).toBe(secondKey.secp256k1Key.toString(16));
    });

    it(`#should be able to input share from web storage after external share deletion, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });
      const reconstructedKey = await tb.reconstructKey();
      const newShare = await tb.generateNewShare();
      await tb.deleteShare(newShare.newShareIndex);
      await tb.syncLocalMetadataTransitions();

      await tb2.initialize();
      await (tb2.modules[WEB_STORAGE_MODULE_NAME] as WebStorageModule).inputShareFromWebStorage();
      const secondKey = await tb2.reconstructKey();
      expect(reconstructedKey.secp256k1Key.toString(16)).toBe(secondKey.secp256k1Key.toString(16));
    });

    it(`#should not be able to input share from web storage after deletion, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await tb.reconstructKey();
      await tb.generateNewShare();
      // @ts-expect-error - deviceShare is not typed
      await tb.deleteShare(resp1.deviceShare.share.shareIndex);
      await tb.syncLocalMetadataTransitions();

      await tb2.initialize();
      await expect(
        (async () => {
          await (tb2.modules[WEB_STORAGE_MODULE_NAME] as WebStorageModule).inputShareFromWebStorage();
          await tb2.reconstructKey();
        })()
      ).rejects.toThrow();
    });

    it(`#should be able to input external share from web storage after deletion, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      const reconstructedKey = await tb.reconstructKey();
      const newShare = await tb.generateNewShare();
      // @ts-expect-error - deviceShare is not typed
      await tb.deleteShare(resp1.deviceShare.share.shareIndex);
      await tb.syncLocalMetadataTransitions();

      await tb2.initialize();
      await expect(
        (async () => {
          await (tb2.modules[WEB_STORAGE_MODULE_NAME] as WebStorageModule).inputShareFromWebStorage();
          await tb2.reconstructKey();
        })()
      ).rejects.toThrow();

      const refreshedShare = newShare.newShareStores[newShare.newShareIndex.toString(16)];
      if (!refreshedShare) throw new Error("expected share store");
      await tb2.inputShareStore(refreshedShare);
      const secondKey = await tb2.reconstructKey();
      expect(reconstructedKey.secp256k1Key.toString(16)).toBe(secondKey.secp256k1Key.toString(16));
    });

    it(`#should be able to add custom device share info, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });
      const reconstructedKey = await tb.reconstructKey();

      const shareDesc = await tb.getMetadata().getShareDescription();
      const deviceShareIndex = Object.keys(shareDesc)[0];
      if (deviceShareIndex === undefined) throw new Error("expected device share index");
      const deviceDescriptions = shareDesc[deviceShareIndex];
      const firstDescription = deviceDescriptions?.[0];
      if (!deviceDescriptions || firstDescription === undefined) throw new Error("expected device share description");

      expect(JSON.parse(firstDescription).customDeviceInfo).toBeUndefined();
      const updatedDeviceShareInfo = { browser: "brave" };
      const newShareDesc = {
        // @ts-expect-error - shareDesc is not typed
        ...JSON.parse(shareDesc[deviceShareIndex]),
        customDeviceInfo: JSON.stringify(updatedDeviceShareInfo),
      };
      await tb.updateShareDescription(deviceShareIndex, firstDescription, JSON.stringify(newShareDesc), true);
      const updatedShareDescs = await tb.getMetadata().getShareDescription();
      const updatedDescription = updatedShareDescs[deviceShareIndex]?.[0];
      if (updatedDescription === undefined) throw new Error("expected updated share description");
      expect(JSON.parse(JSON.parse(updatedDescription).customDeviceInfo)).toStrictEqual(updatedDeviceShareInfo);

      await tb.syncLocalMetadataTransitions();

      await tb2.initialize();
      await (tb2.modules[WEB_STORAGE_MODULE_NAME] as WebStorageModule).inputShareFromWebStorage();
      const secondKey = await tb2.reconstructKey();
      const deviceShareDesc2 = await tb2.getMetadata().getShareDescription();
      expect(secondKey).toStrictEqual(reconstructedKey);
      // @ts-expect-error - deviceShareDesc2 is not typed
      expect(JSON.parse(JSON.parse(deviceShareDesc2[Object.keys(deviceShareDesc2)[0]]).customDeviceInfo)).toStrictEqual(updatedDeviceShareInfo);

      const { newShareStores: newShareStores1, newShareIndex: newShareIndex1 } = await tb2.generateNewShare();
      const newDeviceShareInfo = { device_name: "my home's laptop" };
      const storedDeviceShare = newShareStores1[newShareIndex1.toString(16)];
      if (!storedDeviceShare) throw new Error("expected share store");
      await (tb2.modules[WEB_STORAGE_MODULE_NAME] as WebStorageModule).storeDeviceShare(storedDeviceShare, newDeviceShareInfo);
      const deviceShareDesc3 = await tb2.getMetadata().getShareDescription();
      // @ts-expect-error - deviceShareDesc3 is not typed
      expect(JSON.parse(JSON.parse(deviceShareDesc3[newShareIndex1.toString(16)]).customDeviceInfo)).toStrictEqual(newDeviceShareInfo);
    });
  });
});
