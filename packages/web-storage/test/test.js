import { TKey as ThresholdKey } from "@tkey/core";
import { ServiceProviderBase } from "@tkey/service-provider-base";
import { MockStorageLayer, TorusStorageLayer } from "@tkey/storage-layer-torus";
import { deepStrictEqual, strictEqual, throws } from "assert";

import WebStorageModule, { WEB_STORAGE_MODULE_NAME } from "../src/WebStorageModule";

const rejects = async (fn, error, msg) => {
  let f = () => {};
  try {
    await fn();
  } catch (e) {
    f = () => {
      throw e;
    };
  } finally {
    throws(f, error, msg);
  }
};

function initStorageLayer(mocked, extraParams) {
  return mocked === "true" ? new MockStorageLayer() : new TorusStorageLayer(extraParams);
}

let mocked;
let metadataURL;
const isNode = process.release;
if (!isNode) {
  // eslint-disable-next-line no-undef
  [mocked, metadataURL] = __karma__.config.args;
} else {
  mocked = process.env.MOCKED || "false";
  metadataURL = process.env.METADATA || "http://localhost:5051";
}

const PRIVATE_KEY = "f70fb5f5970b363879bc36f54d4fc0ad77863bfd059881159251f50f48863acc";

const defaultSP = new ServiceProviderBase({ postboxKey: PRIVATE_KEY });
const defaultSL = initStorageLayer(mocked, { hostUrl: metadataURL });

const manualSyncModes = [true, false];
manualSyncModes.forEach((mode) => {
  describe("web storage", function () {
    let tb;
    let tb2;

    beforeEach("Setup ThresholdKey", async function () {
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
      await tb._initializeNewKey({ initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const reconstructedKey = await tb.reconstructKey();
      await tb2.initialize();
      await tb2.modules[WEB_STORAGE_MODULE_NAME].inputShareFromWebStorage();
      const secondKey = await tb2.reconstructKey();
      deepStrictEqual(secondKey, reconstructedKey, "Must be equal");
    });

    it(`#should be able to input share from web storage after reconstruction, manualSync=${mode}`, async function () {
      await tb._initializeNewKey({ initializeModules: true });
      const reconstructedKey = await tb.reconstructKey();
      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      await tb.reconstructKey();
      await tb2.initialize();
      await tb2.modules[WEB_STORAGE_MODULE_NAME].inputShareFromWebStorage();
      const secondKey = await tb2.reconstructKey();
      strictEqual(reconstructedKey.secp256k1Key.toString(16), secondKey.secp256k1Key.toString(16), "Must be equal");
    });

    it(`#should be able to input share from web storage after external share deletion, manualSync=${mode}`, async function () {
      await tb._initializeNewKey({ initializeModules: true });
      const reconstructedKey = await tb.reconstructKey();
      const newShare = await tb.generateNewShare();
      await tb.deleteShare(newShare.newShareIndex.toString(16));
      await tb.syncLocalMetadataTransitions();

      await tb2.initialize();
      await tb2.modules[WEB_STORAGE_MODULE_NAME].inputShareFromWebStorage();
      const secondKey = await tb2.reconstructKey();
      strictEqual(reconstructedKey.secp256k1Key.toString(16), secondKey.secp256k1Key.toString(16), "Must be equal");
    });

    it(`#should not be able to input share from web storage after deletion, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      await tb.reconstructKey();
      // console.log("%O", tb.shares);
      await tb.generateNewShare();
      await tb.deleteShare(resp1.deviceShare.share.shareIndex.toString(16));
      await tb.syncLocalMetadataTransitions();

      // console.log("%O", tb.shares);
      await tb2.initialize();
      // console.log("%O", tb2.shares);
      await rejects(
        async function () {
          await tb2.modules[WEB_STORAGE_MODULE_NAME].inputShareFromWebStorage();
          await tb2.reconstructKey();
        },
        () => {
          return true;
        }
      );
    });

    it(`#should be able to input external share from web storage after deletion, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      const reconstructedKey = await tb.reconstructKey();
      // console.log("%O", tb.shares);
      const newShare = await tb.generateNewShare();
      await tb.deleteShare(resp1.deviceShare.share.shareIndex.toString(16));
      await tb.syncLocalMetadataTransitions();

      await tb2.initialize();

      await rejects(
        async function () {
          await tb2.modules[WEB_STORAGE_MODULE_NAME].inputShareFromWebStorage();
          await tb2.reconstructKey();
        },
        () => {
          return true;
        }
      );

      // console.log("%O", tb2.shares);
      await tb2.inputShareStore(newShare.newShareStores[newShare.newShareIndex.toString(16)]);
      const secondKey = await tb2.reconstructKey();
      strictEqual(reconstructedKey.secp256k1Key.toString(16), secondKey.secp256k1Key.toString(16), "Must be equal");
    });

    it(`#should be able to add custom device share info, manualSync=${mode}`, async function () {
      await tb._initializeNewKey({
        initializeModules: true,
      });
      const reconstructedKey = await tb.reconstructKey();

      const shareDesc = await tb.metadata.getShareDescription();
      const deviceShareIndex = Object.keys(shareDesc)[0];

      deepStrictEqual(JSON.parse(shareDesc[deviceShareIndex][0]).customDeviceInfo, undefined, "device info should be correct");
      const updatedDeviceShareInfo = {
        browser: "brave",
      };
      // update share description
      const oldShareDesc = shareDesc[deviceShareIndex];
      const newShareDesc = { ...JSON.parse(shareDesc[deviceShareIndex]), customDeviceInfo: JSON.stringify(updatedDeviceShareInfo) };
      await tb.updateShareDescription(deviceShareIndex, oldShareDesc[0], JSON.stringify(newShareDesc), true);
      const updatedShareDescs = await tb.metadata.getShareDescription();
      deepStrictEqual(
        JSON.parse(JSON.parse(updatedShareDescs[deviceShareIndex][0]).customDeviceInfo),
        updatedDeviceShareInfo,
        "updated custom device info should be correct"
      );

      await tb.syncLocalMetadataTransitions();

      await tb2.initialize();
      await tb2.modules[WEB_STORAGE_MODULE_NAME].inputShareFromWebStorage();
      const secondKey = await tb2.reconstructKey();
      const deviceShareDesc2 = await tb2.metadata.getShareDescription();
      deepStrictEqual(secondKey, reconstructedKey, "Must be equal");
      deepStrictEqual(
        JSON.parse(JSON.parse(deviceShareDesc2[Object.keys(deviceShareDesc2)[0]]).customDeviceInfo),
        updatedDeviceShareInfo,
        "device info should be correct"
      );

      const { newShareStores: newShareStores1, newShareIndex: newShareIndex1 } = await tb2.generateNewShare();
      const newDeviceShareInfo = {
        device_name: "my home's laptop",
      };
      await tb2.modules[WEB_STORAGE_MODULE_NAME].storeDeviceShare(newShareStores1[newShareIndex1.toString(16)], newDeviceShareInfo);
      const deviceShareDesc3 = await tb2.metadata.getShareDescription();
      deepStrictEqual(
        JSON.parse(JSON.parse(deviceShareDesc3[newShareIndex1.toString(16)]).customDeviceInfo),
        newDeviceShareInfo,
        "new device share info should be correct"
      );
    });
  });
});
