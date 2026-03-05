/* eslint-disable vitest/expect-expect */
/* eslint-disable vitest/no-conditional-expect */
import { bigIntReplacer, getPubKeyPoint, KEY_NOT_FOUND, SHARE_DELETED, ShareStore, type ShareStoreMap } from "@tkey/common-types";
import { Metadata } from "@tkey/core";
import { ED25519Format, PrivateKeyModule, SECP256K1Format } from "@tkey/private-keys";
import { SecurityQuestionsModule } from "@tkey/security-questions";
import { MetamaskSeedPhraseFormat, SeedPhraseModule } from "@tkey/seed-phrase";
import { ServiceProviderBase } from "@tkey/service-provider-base";
import { TorusServiceProvider } from "@tkey/service-provider-torus";
import { ShareTransferModule } from "@tkey/share-transfer";
import { MockStorageLayer, TorusStorageLayer } from "@tkey/storage-layer-torus";
import { generatePrivate } from "@toruslabs/eccrypto";
import { post } from "@toruslabs/http-helpers";
import { bytesToHex, bytesToNumberBE, Hex, hexToBigInt, keccak256, secp256k1, utf8ToBytes } from "@toruslabs/metadata-helpers";
import { getOrSetNonce } from "@toruslabs/torus.js";
import { createPublicClient, http } from "viem";
import { mainnet } from "viem/chains";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

function createEthProvider(rpcUrl: string) {
  const client = createPublicClient({ chain: mainnet, transport: http(rpcUrl) });
  return { getBalance: (address: Hex) => client.getBalance({ address }) };
}

import { TKeyDefault as ThresholdKey } from "../src/index";
import { ed25519Tests } from "./ed25519/ed25519";
import { getMetadataUrl, getServiceProvider, initStorageLayer, isMocked } from "./helpers";

/** Test-only: call private _initializeNewKey (bypass visibility for setup). */
function initializeNewKey(
  t: InstanceType<typeof ThresholdKey>,
  opts?: Parameters<InstanceType<typeof ThresholdKey>["_initializeNewKey"]>[0]
): ReturnType<InstanceType<typeof ThresholdKey>["_initializeNewKey"]> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- intentional test access to private method
  return (t as any)._initializeNewKey(opts);
}

const metadataURL = getMetadataUrl();

function getTempKey() {
  return bytesToHex(generatePrivate());
}
function compareBigintArray(a: bigint[], b: bigint[], message: string) {
  if (a.length !== b.length) throw new Error(message);
  return a.map((el) => {
    const found = b.find((pl) => pl === el);
    if (found === undefined) throw new Error(message);
    return 0;
  });
}

type ReconstructedKeys = {
  secp256k1Key: bigint;
  seedPhraseModule?: bigint[];
  privateKeyModule?: bigint[];
  allKeys?: bigint[];
};

function compareReconstructedKeys(a: ReconstructedKeys, b: ReconstructedKeys, message = "reconstructed keys mismatch") {
  if (a.secp256k1Key !== b.secp256k1Key) throw new Error(message);
  if (a.seedPhraseModule && b.seedPhraseModule) {
    compareBigintArray(a.seedPhraseModule, b.seedPhraseModule, message);
  }
  if (a.privateKeyModule && b.privateKeyModule) {
    compareBigintArray(a.privateKeyModule, b.privateKeyModule, message);
  }
  if (a.allKeys && b.allKeys) {
    compareBigintArray(a.allKeys, b.allKeys, message);
  }
}

export const sharedTestCases = (
  mode: boolean,
  torusSP: InstanceType<typeof TorusServiceProvider> | InstanceType<typeof ServiceProviderBase>,
  storageLayer: InstanceType<typeof TorusStorageLayer> | InstanceType<typeof MockStorageLayer>
) => {
  const customSP = torusSP;
  const customSL = storageLayer;

  describe("tkey", function () {
    let tb: InstanceType<typeof ThresholdKey>;

    beforeEach(async function () {
      tb = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
    });

    it("#should be able to initializeNewKey using initialize and reconstruct it", async function () {
      const sp = customSP;
      sp.postboxKey = hexToBigInt(getTempKey());
      const storageLayer = initStorageLayer({ hostUrl: metadataURL });
      const tb2 = new ThresholdKey({ serviceProvider: sp, storageLayer, manualSync: mode });
      await tb2.initialize();
      const reconstructedKey = await tb2.reconstructKey();
      await tb2.syncLocalMetadataTransitions();
      expect(tb2.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to reconstruct key when initializing a key, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ neverInitializeNewKey: true });
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to reconstruct key when initializing with user input, manualSync=${mode}`, async function () {
      let determinedShare = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      determinedShare = determinedShare % secp256k1.Point.CURVE().n;
      const resp1 = await initializeNewKey(tb, { determinedShare, initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize();
      await tb2.inputShareStoreSafe(resp1.userShare);
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to reconstruct key when initializing with service provider, manualSync=${mode}`, async function () {
      const importedKey = bytesToNumberBE(generatePrivate());
      const resp1 = await initializeNewKey(tb, { importedKey, initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize();
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      expect(reconstructedKey.secp256k1Key).toBe(importedKey);
    });

    it(`#should be able to reconstruct key when initializing a with a share, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.Point.CURVE().n;
      const resp1 = await initializeNewKey(tb, { userInput, initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ withShare: resp1.userShare });
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to reconstruct key after refresh and initializing with a share, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.Point.CURVE().n;
      const resp1 = await initializeNewKey(tb, { userInput, initializeModules: true });
      const newShares = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ withShare: resp1.userShare });
      await tb2.inputShareStoreSafe(newShares.newShareStores[newShares.newShareIndex.toString(16)]);
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to reconstruct key after refresh and initializing with service provider, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.Point.CURVE().n;
      const resp1 = await initializeNewKey(tb, { userInput, initializeModules: true });
      const newShares = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize();
      await tb2.inputShareStoreSafe(newShares.newShareStores[newShares.newShareIndex.toString(16)]);
      const reconstructedKey = await tb2.reconstructKey();
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to reconstruct key, even with old metadata, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize(); // initialize sdk with old metadata

      await tb.generateNewShare(); // generate new share to update metadata
      await tb.syncLocalMetadataTransitions();

      await tb2.inputShareStoreSafe(resp1.deviceShare, true);
      const reconstructedKey = await tb2.reconstructKey(); // reconstruct key with old metadata should work to poly
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to not create a new key if initialize is called with neverInitializeNewKey, manualSync=${mode}`, async function () {
      const newSP = getServiceProvider({ type: torusSP.serviceProviderName });
      const tb2 = new ThresholdKey({ serviceProvider: newSP, storageLayer: customSL });
      await expect(
        (async () => {
          await tb2.initialize({ neverInitializeNewKey: true });
        })()
      ).rejects.toThrow(Error);
    });

    it(`#should be able to output unavailable share store, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      const { newShareStores, newShareIndex } = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ neverInitializeNewKey: true });
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      const shareStore = tb2.outputShareStore(newShareIndex);
      expect(newShareStores[newShareIndex.toString(16)].share.share.toString(16)).toBe(shareStore.share.share.toString(16));

      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to insert shares from existing tkey using _initializeNewKey, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      const { newShareStores: tbShareStore, newShareIndex: tbShareIndex } = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const tb3 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });

      await tb3.initialize({ neverInitializeNewKey: true });
      await tb3.inputShareStoreSafe(resp1.deviceShare, true);
      const reconstructedKey = await tb3.reconstructKey();

      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
      const shareStore = tb3.outputShareStore(tbShareIndex);
      expect(tbShareStore[tbShareIndex.toString(16)].share.share.toString(16)).toBe(shareStore.share.share.toString(16));
    });

    it(`#should be able to insert shares from existing tkey using new TKey Instance, manualSync=${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      const resp2 = await initializeNewKey(tb2, { initializeModules: true });
      await tb2.syncLocalMetadataTransitions();

      const tb3 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });

      await tb3.initialize({ neverInitializeNewKey: true });
      await tb3.inputShareStoreSafe(resp2.deviceShare, true);
      const reconstructedKey = await tb3.reconstructKey();
      expect(resp2.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#shouldn't be able to insert shares from random threshold key, manualSync=${mode}`, async function () {
      // wrong tkey instance
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      const { newShareStores: tbShareStore, newShareIndex: tbShareIndex } = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      // tkey instance with correct share stores and index
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      const resp2 = await initializeNewKey(tb2, { initializeModules: true });
      await tb2.syncLocalMetadataTransitions();

      const tb3 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb3.initialize({ neverInitializeNewKey: true });
      await tb3.syncLocalMetadataTransitions();

      // throws since share doesn't
      await expect(
        (async () => {
          await tb3.inputShareStoreSafe(tbShareStore[tbShareIndex.toString(16)], true);
        })()
      ).rejects.toMatchObject({ code: 1307 });
      await expect(
        (async () => {
          await tb3.inputShareStoreSafe(resp1.deviceShare, true);
        })()
      ).rejects.toMatchObject({ code: 1307 });
      // should be able to insert if correct share store and index
      await tb3.inputShareStoreSafe(resp2.deviceShare, true);
      await tb3.reconstructKey();
      const { newShareStores: tb3ShareStore, newShareIndex: tb3ShareIndex } = await tb3.generateNewShare();
      await tb3.syncLocalMetadataTransitions();
      await tb3.reconstructKey();

      await tb2.inputShareStoreSafe(tb3ShareStore[tb3ShareIndex.toString(16)], true);
      const reconstructedKey2 = await tb2.reconstructKey();
      expect(resp2.secp256k1Key).toBe(reconstructedKey2.secp256k1Key);
    });

    it(`#should be able to update metadata, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await tb.syncLocalMetadataTransitions();
      // nonce 0

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize();
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      await tb2.reconstructKey();

      // try creating new shares
      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      // In autoSync, generateNewShare will throw
      // in manualSync, syncLocalMetadataTransitions will throw
      await expect(
        (async () => {
          await tb2.generateNewShare();
          await tb2.syncLocalMetadataTransitions();
        })()
      ).rejects.toThrow(Error);

      // try creating again
      const newtb = await tb2.updateSDK();
      await newtb.reconstructKey();
      await newtb.generateNewShare();
      await newtb.syncLocalMetadataTransitions();
    });
  });

  describe(`tkey share deletion, manualSync=${mode}`, function () {
    let deletedShareIndex: bigint;
    let deletedShareStores: ShareStoreMap;
    let shareStoreAfterDelete: ShareStoreMap;
    let tb: InstanceType<typeof ThresholdKey>;
    let tbInitResp: Awaited<ReturnType<typeof initializeNewKey>>;

    beforeAll(async function () {
      tb = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      tbInitResp = await initializeNewKey(tb, { initializeModules: true });
      const newShare = await tb.generateNewShare();
      const updatedShareStore = await tb.deleteShare(newShare.newShareIndex);
      deletedShareIndex = newShare.newShareIndex;
      deletedShareStores = newShare.newShareStores;
      shareStoreAfterDelete = updatedShareStore.newShareStores;
      await tb.syncLocalMetadataTransitions();
    });

    it(`#should be not be able to lookup delete share, manualSync=${mode}`, async function () {
      const newKeys = Object.keys(shareStoreAfterDelete);
      expect(newKeys.find((el) => el === deletedShareIndex.toString(16))).toBeUndefined();
    });

    it(`#should not be able to delete more than threshold number of shares, manualSync=${mode}`, async function () {
      const { newShareIndex: newShareIndex1 } = await tb.generateNewShare();
      await tb.deleteShare(newShareIndex1);
      await tb.syncLocalMetadataTransitions();
      await expect(
        (async () => {
          await tb.deleteShare(tbInitResp.deviceShare.share.shareIndex);
        })()
      ).rejects.toThrow(Error);
    });

    it(`#should not be able to initialize with a deleted share, manualSync=${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await expect(
        (async () => {
          await tb2.initialize({ withShare: deletedShareStores[deletedShareIndex.toString(16)] });
        })()
      ).rejects.toThrow();
    });

    it(`#should not be able to add share post deletion, manualSync=${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize();
      await expect(
        (async () => {
          await tb2.inputShare(deletedShareStores[deletedShareIndex.toString(16)].share.share);
        })()
      ).rejects.toThrow(Error);
    });

    it(`#should be able to delete a user, manualSync=${mode}`, async function () {
      // create 2/4
      await initializeNewKey(tb, { initializeModules: true });
      await tb.generateNewShare();
      const shareStoresAtEpoch2 = tb.getAllShareStoresForLatestPolynomial();

      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();
      const sharesStoresAtEpoch3 = tb.getAllShareStoresForLatestPolynomial();
      await tb.CRITICAL_deleteTkey();

      const spData = await customSL.getMetadata({ serviceProvider: customSP });
      const data2 = await Promise.allSettled(shareStoresAtEpoch2.map((x) => tb.catchupToLatestShare({ shareStore: x })));
      const data3 = await Promise.all(sharesStoresAtEpoch3.map((x) => customSL.getMetadata({ privKey: x.share.share })));

      expect((spData as { message: string }).message).toStrictEqual(KEY_NOT_FOUND);

      data2.forEach((x) => {
        expect(x.status).toStrictEqual("rejected");
        expect((x as PromiseRejectedResult).reason.code).toStrictEqual(1308);
      });

      data3.forEach((x) => {
        expect((x as { message: string }).message).toStrictEqual(SHARE_DELETED);
      });
    });

    it(`#should be able to reinitialize after wipe, manualSync=${mode}`, async function () {
      // create 2/4
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await tb.generateNewShare();
      if (mode) {
        await tb.syncLocalMetadataTransitions();
      }
      await tb.CRITICAL_deleteTkey();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize();
      await tb2.generateNewShare();
      if (mode) {
        await tb2.syncLocalMetadataTransitions();
      }

      const data3 = await customSL.getMetadata({ serviceProvider: customSP });
      expect((data3 as { message: string }).message).not.toBe(KEY_NOT_FOUND);
      expect(tb2.metadata.nonce).toStrictEqual(1);

      const reconstructedKey = await tb2.reconstructKey();
      expect(resp1.secp256k1Key).not.toBe(reconstructedKey.secp256k1Key);
    });
  });

  describe("tkey serialization/deserialization", function () {
    let tb: InstanceType<typeof ThresholdKey>;

    beforeEach(async function () {
      tb = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
    });

    it(`#should serialize and deserialize correctly without tkeyArgs, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.Point.CURVE().n;
      const resp1 = await initializeNewKey(tb, { userInput, initializeModules: true });
      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const stringified = JSON.stringify(tb, bigIntReplacer);
      const tb3 = await ThresholdKey.fromJSON(JSON.parse(stringified));
      const finalKey = await tb3.reconstructKey();
      expect(finalKey.secp256k1Key.toString(16)).toBe(resp1.secp256k1Key.toString(16));
    });

    it(`#should serialize and deserialize correctly with tkeyArgs, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.Point.CURVE().n;
      const resp1 = await initializeNewKey(tb, { userInput, initializeModules: true });
      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const stringified = JSON.stringify(tb, bigIntReplacer);
      const tb3 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: customSP, storageLayer: customSL });
      const finalKey = await tb3.reconstructKey();
      expect(finalKey.secp256k1Key.toString(16)).toBe(resp1.secp256k1Key.toString(16));
    });

    it(`#should serialize and deserialize correctly, keeping localTransitions consistent before syncing NewKeyAssign, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.Point.CURVE().n;
      const resp1 = await initializeNewKey(tb, { userInput, initializeModules: true });

      // generate and delete
      const { newShareIndex: shareIndex1 } = await tb.generateNewShare();
      await tb.deleteShare(shareIndex1);

      const { newShareStores: shareStores, newShareIndex: shareIndex } = await tb.generateNewShare();

      const stringified = JSON.stringify(tb, bigIntReplacer);
      const tb2 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: customSP, storageLayer: customSL });
      expect(tb2.manualSync).toBe(mode);
      const finalKey = await tb2.reconstructKey();
      const shareToVerify = tb2.outputShareStore(shareIndex);
      expect(shareStores[shareIndex.toString(16)].share.share.toString(16)).toBe(shareToVerify.share.share.toString(16));
      await tb2.syncLocalMetadataTransitions();
      expect(finalKey.secp256k1Key.toString(16)).toBe(resp1.secp256k1Key.toString(16));

      const reconstructedKey2 = await tb2.reconstructKey();
      expect(resp1.secp256k1Key).toBe(reconstructedKey2.secp256k1Key);
    });

    it(`#should serialize and deserialize correctly keeping localTransitions afterNewKeyAssign, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.Point.CURVE().n;
      const resp1 = await initializeNewKey(tb, { userInput, initializeModules: true });
      await tb.syncLocalMetadataTransitions();
      const reconstructedKey = await tb.reconstructKey();
      const { newShareStores: shareStores, newShareIndex: shareIndex } = await tb.generateNewShare();

      const stringified = JSON.stringify(tb, bigIntReplacer);
      const tb2 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: customSP, storageLayer: customSL });
      const finalKey = await tb2.reconstructKey();
      const shareToVerify = tb2.outputShareStore(shareIndex);
      expect(shareStores[shareIndex.toString(16)].share.share.toString(16)).toBe(shareToVerify.share.share.toString(16));
      await tb2.syncLocalMetadataTransitions();
      expect(finalKey.secp256k1Key.toString(16)).toBe(reconstructedKey.secp256k1Key.toString(16));

      const reconstructedKey2 = await tb2.reconstructKey();
      expect(resp1.secp256k1Key).toBe(reconstructedKey2.secp256k1Key);
    });

    it(`#should be able to reshare a key and retrieve from service provider serialization, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      const { newShareStores, newShareIndex } = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();
      const tb3 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb3.initialize();
      await tb3.inputShareStoreSafe(newShareStores[newShareIndex.toString(16)]);

      const stringified = JSON.stringify(tb3, bigIntReplacer);
      const tb4 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      const finalKeyPostSerialization = await tb4.reconstructKey();
      expect(finalKeyPostSerialization.secp256k1Key.toString(16)).toBe(resp1.secp256k1Key.toString(16));
    });

    it(`#should be able to serialize and deserialize without service provider share or the postbox key, manualSync=${mode}`, async function () {
      const customSP2 = getServiceProvider({ type: torusSP.serviceProviderName });
      const customSL2 = initStorageLayer({ hostUrl: metadataURL });
      const tb = new ThresholdKey({ serviceProvider: customSP2, storageLayer: customSL2, manualSync: mode });
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      const { newShareStores: newShareStores1, newShareIndex: newShareIndex1 } = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const customSP3 = getServiceProvider({ type: torusSP.serviceProviderName, isEmptyProvider: true });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test-only: assign serviceProvider to storage layer
      (customSL2 as any).serviceProvider = customSP3;
      const tb2 = new ThresholdKey({ serviceProvider: customSP3, storageLayer: customSL2, manualSync: mode });
      await tb2.initialize({ withShare: resp1.deviceShare });
      await tb2.inputShareStoreSafe(newShareStores1[newShareIndex1.toString(16)]);
      await tb2.reconstructKey();
      const stringified = JSON.stringify(tb2, bigIntReplacer);

      const tb3 = await ThresholdKey.fromJSON(JSON.parse(stringified));
      const tb3Key = await tb3.reconstructKey();
      expect(tb3Key.secp256k1Key.toString(16)).toBe(resp1.secp256k1Key.toString(16));
    });

    it(`#should not be able to updateSDK with newKeyAssign transitions unsynced, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });
      const stringified = JSON.stringify(tb, bigIntReplacer);
      const tb2 = await ThresholdKey.fromJSON(JSON.parse(stringified), {});

      if (mode) {
        // Can't updateSDK, please do key assign.
        await expect(
          (async () => {
            await tb2.updateSDK();
          })()
        ).rejects.toThrow(Error);
      }

      // create new key because the state might have changed after updateSDK()
      const tb3 = await ThresholdKey.fromJSON(JSON.parse(stringified), {});
      await tb3.generateNewShare();
      await tb3.syncLocalMetadataTransitions();
      await tb3.updateSDK();
    });
  });

  describe("StorageLayer", function () {
    it(`#should get or set correctly, manualSync=${mode}`, async function () {
      const tsp = getServiceProvider({ type: torusSP.serviceProviderName });
      const storageLayer = initStorageLayer({ hostUrl: metadataURL });
      const message = { test: Math.random().toString(36).substring(7) };
      await storageLayer.setMetadata({ input: message, privKey: tsp.postboxKey });
      const resp = await storageLayer.getMetadata({ privKey: tsp.postboxKey });
      expect(resp).toStrictEqual(message);
    });

    it(`#should get or set with specified private key correctly, manualSync=${mode}`, async function () {
      const privKey = bytesToHex(generatePrivate());
      const privKeyBN = hexToBigInt(privKey);
      const storageLayer = initStorageLayer({ hostUrl: metadataURL });
      const message = { test: Math.random().toString(36).substring(7) };
      await storageLayer.setMetadata({ input: message, privKey: privKeyBN });
      const resp = await storageLayer.getMetadata({ privKey: privKeyBN });
      expect(resp).toStrictEqual(message);
    });

    it(`#should be able to get/set bulk correctly, manualSync=${mode}`, async function () {
      const privkeys = [];
      const messages = [];
      for (let i = 0; i < 10; i += 1) {
        privkeys.push(bytesToNumberBE(generatePrivate()));
        messages.push({ test: Math.random().toString(36).substring(7) });
      }
      const storageLayer = initStorageLayer({ hostUrl: metadataURL });
      await storageLayer.setMetadataStream({ input: [...messages], privKey: [...privkeys] });
      const responses = await Promise.all(privkeys.map((el) => storageLayer.getMetadata({ privKey: el })));
      for (let i = 0; i < 10; i += 1) {
        expect(responses[i]).toStrictEqual(messages[i]);
      }
    });
  });

  describe("SecurityQuestionsModule", function () {
    let tb: InstanceType<typeof ThresholdKey>;

    beforeEach(async function () {
      tb = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
        manualSync: mode,
      });
    });

    it(`#should be able to reconstruct key and initialize a key with security questions, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await expect(
        (async () => {
          await (tb.modules.securityQuestions as SecurityQuestionsModule).inputShareFromSecurityQuestions("blublu");
        })()
      ).rejects.toThrow(Error);

      await (tb.modules.securityQuestions as SecurityQuestionsModule).generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
      await tb.syncLocalMetadataTransitions();
      const question = (tb.modules.securityQuestions as SecurityQuestionsModule).getSecurityQuestions();
      expect(question).toBe("who is your cat?");
      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb2.initialize();

      // wrong password
      await expect(
        (async () => {
          await (tb.modules.securityQuestions as SecurityQuestionsModule).inputShareFromSecurityQuestions("blublu-wrong");
        })()
      ).rejects.toThrow(Error);

      await (tb2.modules.securityQuestions as SecurityQuestionsModule).inputShareFromSecurityQuestions("blublu");
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to delete and add security questions, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await (tb.modules.securityQuestions as SecurityQuestionsModule).generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      // delete sq
      const sqIndex = (tb.metadata.generalStore as { securityQuestions: { shareIndex: bigint } }).securityQuestions.shareIndex;
      await tb.deleteShare(sqIndex);

      // add sq again
      await (tb.modules.securityQuestions as SecurityQuestionsModule).generateNewShareWithSecurityQuestions("blubluss", "who is your cat?");
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb2.initialize();

      await (tb2.modules.securityQuestions as SecurityQuestionsModule).inputShareFromSecurityQuestions("blubluss");
      const reconstructedKey = await tb2.reconstructKey();
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to reconstruct key and initialize a key with security questions after refresh, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await (tb.modules.securityQuestions as SecurityQuestionsModule).generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      await tb2.initialize();

      await (tb2.modules.securityQuestions as SecurityQuestionsModule).inputShareFromSecurityQuestions("blublu");
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to change password, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });

      // should throw
      await expect(
        (async () => {
          await (tb.modules.securityQuestions as SecurityQuestionsModule).changeSecurityQuestionAndAnswer("dodo", "who is your cat?");
        })()
      ).rejects.toThrow(Error);

      await (tb.modules.securityQuestions as SecurityQuestionsModule).generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
      await (tb.modules.securityQuestions as SecurityQuestionsModule).changeSecurityQuestionAndAnswer("dodo", "who is your cat?");
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb2.initialize();

      await (tb2.modules.securityQuestions as SecurityQuestionsModule).inputShareFromSecurityQuestions("dodo");
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to change password and serialize, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await (tb.modules.securityQuestions as SecurityQuestionsModule).generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
      await (tb.modules.securityQuestions as SecurityQuestionsModule).changeSecurityQuestionAndAnswer("dodo", "who is your cat?");
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb2.initialize();

      await (tb2.modules.securityQuestions as SecurityQuestionsModule).inputShareFromSecurityQuestions("dodo");
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);

      const stringified = JSON.stringify(tb2, bigIntReplacer);
      const tb3 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: customSP, storageLayer: customSL });
      const finalKeyPostSerialization = await tb3.reconstructKey();
      expect(finalKeyPostSerialization.secp256k1Key.toString(16)).toBe(reconstructedKey.secp256k1Key.toString(16));
    });

    it(`#should be able to get answers, even when they change, manualSync=${mode}`, async function () {
      tb = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule(true) },
      });
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      const qn = "who is your cat?";
      const ans1 = "blublu";
      const ans2 = "dodo";
      await (tb.modules.securityQuestions as SecurityQuestionsModule).generateNewShareWithSecurityQuestions(ans1, qn);
      let gotAnswer = await (tb.modules.securityQuestions as SecurityQuestionsModule).getAnswer();
      expect(gotAnswer).toBe(ans1);
      await (tb.modules.securityQuestions as SecurityQuestionsModule).changeSecurityQuestionAndAnswer(ans2, qn);
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule(true) },
      });
      await tb2.initialize();

      await (tb2.modules.securityQuestions as SecurityQuestionsModule).inputShareFromSecurityQuestions("dodo");
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);

      gotAnswer = await (tb2.modules.securityQuestions as SecurityQuestionsModule).getAnswer();
      expect(gotAnswer).toBe(ans2);
    });
  });

  describe("ShareTransferModule", function () {
    let tb: InstanceType<typeof ThresholdKey>;

    beforeEach(async function () {
      tb = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
        modules: { shareTransfer: new ShareTransferModule() },
      });
    });

    it(`#should be able to transfer share via the module, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      const result = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
        modules: { shareTransfer: new ShareTransferModule() },
      });
      await tb2.initialize();

      // usually should be called in callback, but mocha does not allow
      const pubkey = await (tb2.modules.shareTransfer as ShareTransferModule).requestNewShare("unit test", []);

      await (tb.modules.shareTransfer as ShareTransferModule).approveRequest(pubkey, result.newShareStores[result.newShareIndex.toString(16)]);
      await tb.syncLocalMetadataTransitions();

      await (tb2.modules.shareTransfer as ShareTransferModule).startRequestStatusCheck(pubkey, false);

      const reconstructedKey = await tb2.reconstructKey();
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to change share transfer pointer after share deletion, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });
      type ShareTransferStore = { pointer: bigint };
      const gs = () => (tb.metadata.generalStore as { shareTransfer: ShareTransferStore }).shareTransfer;
      const firstShareTransferPointer = gs().pointer.toString(16);
      const { newShareIndex: newShareIndex1 } = await tb.generateNewShare();
      const secondShareTransferPointer = gs().pointer.toString(16);

      expect(firstShareTransferPointer).toBe(secondShareTransferPointer);

      await tb.syncLocalMetadataTransitions();
      await tb.deleteShare(newShareIndex1);
      const thirdShareTransferPointer = gs().pointer.toString(16);

      expect(secondShareTransferPointer).not.toStrictEqual(thirdShareTransferPointer);
      await tb.syncLocalMetadataTransitions();
    });

    it(`#should be able to transfer device share, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
        modules: { shareTransfer: new ShareTransferModule() },
      });
      await tb2.initialize();
      const currentShareIndexes = tb2.getCurrentShareIndexes();
      // usually should be called in callback, but mocha does not allow
      const pubkey = await (tb2.modules.shareTransfer as ShareTransferModule).requestNewShare("unit test", currentShareIndexes);

      const requests = await (tb.modules.shareTransfer as ShareTransferModule).getShareTransferStore();
      const pubkey2 = Object.keys(requests)[0];
      await (tb.modules.shareTransfer as ShareTransferModule).approveRequest(pubkey2);

      await (tb2.modules.shareTransfer as ShareTransferModule).startRequestStatusCheck(pubkey, true);

      // await new Promise((res) => {
      //   setTimeout(res, 1001);
      // });

      const reconstructedKey = await tb2.reconstructKey();
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });

    it(`#should be able to delete share transfer from another device, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
        modules: { shareTransfer: new ShareTransferModule() },
      });
      await tb2.initialize();

      // usually should be called in callback, but mocha does not allow
      const encKey2 = await (tb2.modules.shareTransfer as ShareTransferModule).requestNewShare("unit test", []);
      await (tb.modules.shareTransfer as ShareTransferModule).deleteShareTransferStore(encKey2); // delete 1st request from 2nd
      const newRequests = await (tb2.modules.shareTransfer as ShareTransferModule).getShareTransferStore();
      expect(encKey2 in newRequests).toBe(false);
    });

    it(`#should be able to reset share transfer store, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      await (tb.modules.shareTransfer as ShareTransferModule).resetShareTransferStore();
      const stStore = await (tb.modules.shareTransfer as ShareTransferModule).getShareTransferStore();
      expect((stStore as unknown as { message: string }).message).toBe(KEY_NOT_FOUND);
    });
  });

  describe("ShareSerializationModule", function () {
    it(`#should be able to serialize and deserialize share, manualSync=${mode}`, async function () {
      const tb = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
      });
      const resp1 = await initializeNewKey(tb, { initializeModules: true });

      // should throw
      await expect(
        (async () => {
          await tb.outputShare(resp1.deviceShare.share.shareIndex, "mnemonic-49");
        })()
      ).rejects.toThrow();

      const exportedSeedShare = await tb.outputShare(resp1.deviceShare.share.shareIndex, "mnemonic");
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
      });
      await tb2.initialize();

      // should throw
      await expect(
        (async () => {
          await tb2.inputShare(String(exportedSeedShare), "mnemonic-49");
        })()
      ).rejects.toThrow();

      await tb2.inputShare(String(exportedSeedShare), "mnemonic");
      const reconstructedKey = await tb2.reconstructKey();

      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
    });
  });

  describe("TkeyStore", function () {
    let tb: InstanceType<typeof ThresholdKey>;
    let metamaskSeedPhraseFormat: InstanceType<typeof MetamaskSeedPhraseFormat>;
    let secp256k1Format: InstanceType<typeof SECP256K1Format>;
    let ed25519privateKeyFormat: InstanceType<typeof ED25519Format>;

    beforeEach(async function () {
      metamaskSeedPhraseFormat = new MetamaskSeedPhraseFormat(createEthProvider(process.env.TEST_RPC_TARGET));
      secp256k1Format = new SECP256K1Format(0n);
      ed25519privateKeyFormat = new ED25519Format(0n);
      tb = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
        modules: {
          seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat]),
          privateKeyModule: new PrivateKeyModule([secp256k1Format, ed25519privateKeyFormat]),
        },
      });
    });

    it(`#should not to able to initalize without seedphrase formats, manualSync=${mode}`, async function () {
      const seedPhraseToSet = "seed sock milk update focus rotate barely fade car face mechanic mercy";
      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
        modules: { seedPhrase: new SeedPhraseModule([]), privateKeyModule: new PrivateKeyModule([]) },
      });
      await initializeNewKey(tb2, { initializeModules: true });
      // should throw
      await expect(
        (async () => {
          await (tb2.modules.seedPhrase as SeedPhraseModule).setSeedPhrase("HD Key Tree", seedPhraseToSet);
        })()
      ).rejects.toThrow(Error);

      await expect(
        (async () => {
          await (tb2.modules.seedPhrase as SeedPhraseModule).setSeedPhrase("HD Key Tree", `${seedPhraseToSet}123`);
        })()
      ).rejects.toThrow(Error);

      // should throw
      await expect(
        (async () => {
          const actualPrivateKeys = [BigInt("0x4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390")];
          await (tb2.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("secp256k1n", actualPrivateKeys[0]);
        })()
      ).rejects.toThrow(Error);

      await expect(
        (async () => {
          const actualPrivateKeys = [BigInt("0x4bd0041a9b16a7268a5de7982f2422b15635c4fd170c140dc48976wqerwer0")];
          await (tb2.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("secp256k1n", actualPrivateKeys[0]);
        })()
      ).rejects.toThrow(Error);
    });

    it(`#should get/set multiple seed phrase, manualSync=${mode}`, async function () {
      const seedPhraseToSet = "seed sock milk update focus rotate barely fade car face mechanic mercy";
      const seedPhraseToSet2 = "object brass success calm lizard science syrup planet exercise parade honey impulse";
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await (tb.modules.seedPhrase as SeedPhraseModule).setSeedPhrase("HD Key Tree", seedPhraseToSet);
      await (tb.modules.seedPhrase as SeedPhraseModule).setSeedPhrase("HD Key Tree", seedPhraseToSet2);
      await tb.syncLocalMetadataTransitions();
      const returnedSeed = await (tb.modules.seedPhrase as SeedPhraseModule).getSeedPhrases();
      expect(returnedSeed[0].seedPhrase).toBe(seedPhraseToSet);
      expect(returnedSeed[1].seedPhrase).toBe(seedPhraseToSet2);

      const metamaskSeedPhraseFormat2 = new MetamaskSeedPhraseFormat(createEthProvider(process.env.TEST_RPC_TARGET));
      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
        modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat2]) },
      });
      await tb2.initialize();
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstuctedKey = await tb2.reconstructKey();
      await (tb.modules.seedPhrase as SeedPhraseModule).getSeedPhrasesWithAccounts();

      compareReconstructedKeys(reconstuctedKey as ReconstructedKeys, {
        secp256k1Key: resp1.secp256k1Key,
        seedPhraseModule: [
          BigInt("0x70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46"),
          BigInt("0xbfdb025a1d404212c3f9ace6c5fb4185087281dcb9c1e89087d1a3a423f80d22"),
        ],
        allKeys: [
          resp1.secp256k1Key,
          BigInt("0x70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46"),
          BigInt("0xbfdb025a1d404212c3f9ace6c5fb4185087281dcb9c1e89087d1a3a423f80d22"),
        ],
      });
    });

    it(`#should be able to derive keys, manualSync=${mode}`, async function () {
      const seedPhraseToSet = "seed sock milk update focus rotate barely fade car face mechanic mercy";
      await initializeNewKey(tb, { initializeModules: true });
      await (tb.modules.seedPhrase as SeedPhraseModule).setSeedPhrase("HD Key Tree", seedPhraseToSet);
      await tb.syncLocalMetadataTransitions();

      const actualPrivateKeys = [BigInt("0x70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46")];
      const derivedKeys = await (tb.modules.seedPhrase as SeedPhraseModule).getAccounts();
      compareBigintArray(actualPrivateKeys, derivedKeys, "key should be same");
    });

    it(`#should be able to generate seed phrase if not given, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });
      await (tb.modules.seedPhrase as SeedPhraseModule).setSeedPhrase("HD Key Tree");
      await tb.syncLocalMetadataTransitions();

      const [seed] = await (tb.modules.seedPhrase as SeedPhraseModule).getSeedPhrases();
      const derivedKeys = await (tb.modules.seedPhrase as SeedPhraseModule).getAccounts();
      expect(metamaskSeedPhraseFormat.validateSeedPhrase(seed.seedPhrase)).toBeTruthy();
      expect(derivedKeys.length >= 1).toBeTruthy();
    });

    it(`#should be able to change seedphrase, manualSync=${mode}`, async function () {
      const oldSeedPhrase = "verb there excuse wink merge phrase alien senior surround fluid remind chef bar move become";
      await initializeNewKey(tb, { initializeModules: true });
      await (tb.modules.seedPhrase as SeedPhraseModule).setSeedPhrase("HD Key Tree", oldSeedPhrase);
      // await (tb.modules.seedPhrase as SeedPhraseModule).setSeedPhrase("HD Key Tree");
      await tb.syncLocalMetadataTransitions();

      const newSeedPhrase = "trim later month olive fit shoulder entry laptop jeans affair belt drip jealous mirror fancy";
      await (tb.modules.seedPhrase as SeedPhraseModule).CRITICAL_changeSeedPhrase(oldSeedPhrase, newSeedPhrase);
      await tb.syncLocalMetadataTransitions();

      const secondStoredSeedPhrases = await (tb.modules.seedPhrase as SeedPhraseModule).getSeedPhrases();

      expect(secondStoredSeedPhrases[0].seedPhrase).toBe(newSeedPhrase);
    });

    it(`#should be able to replace numberOfWallets seed phrase module, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });
      await (tb.modules.seedPhrase as SeedPhraseModule).setSeedPhrase("HD Key Tree");
      await (tb.modules.seedPhrase as SeedPhraseModule).setSeedPhrase("HD Key Tree");
      const seedPhraseStores = await (tb.modules.seedPhrase as SeedPhraseModule).getSeedPhrases();
      await (tb.modules.seedPhrase as SeedPhraseModule).setSeedPhraseStoreItem({
        id: seedPhraseStores[1].id,
        seedPhrase: seedPhraseStores[1].seedPhrase,
        numberOfWallets: 2,
      } as unknown as import("@tkey/common-types").ISeedPhraseStore);
      await tb.syncLocalMetadataTransitions();

      const secondStoredSeedPhrases = await (tb.modules.seedPhrase as SeedPhraseModule).getSeedPhrases();
      expect((secondStoredSeedPhrases[0] as unknown as { numberOfWallets: number }).numberOfWallets).toBe(1);
      expect((secondStoredSeedPhrases[1] as unknown as { numberOfWallets: number }).numberOfWallets).toBe(2);
    });

    it(`#should be able to get/set private key, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });

      const actualPrivateKeys = [
        BigInt("0x4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390"),
        BigInt("0x1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0"),
        BigInt("0x7a3118ccdd405b2750271f51cc8fe237d9863584173aec3fa4579d40e5b4951215351c3d54ef416e49567b79c42fd985fcda60a6da9a794e4e844ac8dec47e98"),
      ];
      await (tb.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("secp256k1n", actualPrivateKeys[0]);
      await (tb.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("secp256k1n", actualPrivateKeys[1]);
      await (tb.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("ed25519", actualPrivateKeys[2]);
      await tb.syncLocalMetadataTransitions();
      await (tb.modules.privateKeyModule as PrivateKeyModule).getAccounts();

      const getAccounts = await (tb.modules.privateKeyModule as PrivateKeyModule).getAccounts();
      expect(actualPrivateKeys.map((x) => x.toString(16))).toStrictEqual(getAccounts.map((x) => x.toString(16)));
    });

    it(`#should be able to get/set private key, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });

      const actualPrivateKeys = [
        BigInt("0x4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390"),
        BigInt("0x1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0"),
        BigInt("0x99da9559e15e913ee9ab2e53e3dfad575da33b49be1125bb922e33494f4988281b2f49096e3e5dbd0fcfa9c0c0cd92d9ab3b21544b34d5dd4a65d98b878b9922"),
      ];

      await (tb.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("secp256k1n", actualPrivateKeys[0]);
      await (tb.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("secp256k1n", actualPrivateKeys[1]);
      await (tb.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("ed25519", actualPrivateKeys[2]);
      await tb.syncLocalMetadataTransitions();
      await (tb.modules.privateKeyModule as PrivateKeyModule).getAccounts();

      const getAccounts = await (tb.modules.privateKeyModule as PrivateKeyModule).getAccounts();
      expect(actualPrivateKeys.map((x) => x.toString(16))).toStrictEqual(getAccounts.map((x) => x.toString(16)));
    });

    it(`#should be able to generate private key if not given, manualSync=${mode}`, async function () {
      await initializeNewKey(tb, { initializeModules: true });

      await (tb.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("secp256k1n");
      await (tb.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("secp256k1n");
      await (tb.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("ed25519");
      await tb.syncLocalMetadataTransitions();

      const accounts = await (tb.modules.privateKeyModule as PrivateKeyModule).getAccounts();
      expect(accounts.length).toBe(3);
    });

    it(`#should be able to get/set private keys and seed phrase, manualSync=${mode}`, async function () {
      const resp1 = await initializeNewKey(tb, { initializeModules: true });

      await (tb.modules.seedPhrase as SeedPhraseModule).setSeedPhrase(
        "HD Key Tree",
        "seed sock milk update focus rotate barely fade car face mechanic mercy"
      );
      await (tb.modules.seedPhrase as SeedPhraseModule).setSeedPhrase(
        "HD Key Tree",
        "chapter gas cost saddle annual mouse chef unknown edit pen stairs claw"
      );

      const actualPrivateKeys = [
        BigInt("0x4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390"),
        BigInt("0x1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0"),
      ];
      await (tb.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("secp256k1n", actualPrivateKeys[0]);
      await (tb.modules.privateKeyModule as PrivateKeyModule).setPrivateKey("secp256k1n", actualPrivateKeys[1]);
      await tb.syncLocalMetadataTransitions();

      const reconstructedKey2 = await tb.reconstructKey(false);
      compareReconstructedKeys(reconstructedKey2 as ReconstructedKeys, {
        secp256k1Key: resp1.secp256k1Key,
        allKeys: [resp1.secp256k1Key],
      });
    });

    it(`#should be able to increase threshold limit of tkey, manualSync=${mode}`, async function () {
      // tkey instance with correct share stores and index
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      const resp2 = await initializeNewKey(tb2, { initializeModules: true });
      await tb2.syncLocalMetadataTransitions();

      const tb3 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb3.initialize({ neverInitializeNewKey: true });

      // should be able to insert if correct share store and index
      await tb3.inputShareStoreSafe(resp2.deviceShare, true);
      await tb3.reconstructKey();

      // generate new shares
      await tb3.generateNewShare();
      await tb3.generateNewShare();
      await tb3.syncLocalMetadataTransitions();

      // reconstruct tkey
      const reconstructPreThreshold = await tb3.reconstructKey();

      const poly = tb3.metadata.getLatestPublicPolynomial();
      const existingShareIndexes = tb3.metadata.getShareIndexesForPolynomial(poly.getPolynomialID());

      // increase threshold from 2 -> 3
      const newThreshold = 3;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test-only: access private method
      await (tb3 as any)._refreshShares(newThreshold, existingShareIndexes, poly.getPolynomialID());

      // 3/4 shares is required to reconstruct tkey
      const reconstructPostThreshold = await tb3.reconstructKey();
      expect(reconstructPreThreshold.secp256k1Key).toBe(reconstructPostThreshold.secp256k1Key);
      // console.log("newThreshold", tb3.metadata.getLatestPublicPolynomial().getThreshold());
      expect(tb3.metadata.getLatestPublicPolynomial().getThreshold()).toBe(newThreshold);
    });
  });

  describe("Tkey LocalMetadataTransition", function () {
    it("should able to get latest share from getGenericMetadataWithTransitionStates with localMetadataTransision", async function () {
      const tb = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: true,
        storageLayer: customSL,
      });

      await initializeNewKey(tb);

      await tb.reconstructKey();

      await tb.generateNewShare();

      const expectLatestSPShare = await tb.getGenericMetadataWithTransitionStates({
        fromJSONConstructor: ShareStore,
        serviceProvider: customSP,
        includeLocalMetadataTransitions: true,
        _localMetadataTransitions: tb._localMetadataTransitions,
      });

      const latestSPShareStore = tb.outputShareStore(1n);

      expect(JSON.stringify(latestSPShareStore.toJSON())).toBe(JSON.stringify((expectLatestSPShare as ShareStore).toJSON()));
    });

    it("should able to get catchupToLatestShare with localMetadataTransision", async function () {
      const tb = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: true,
        storageLayer: customSL,
      });

      await initializeNewKey(tb);
      const spShareStore = tb.outputShareStore(1n);

      await tb.reconstructKey();

      await tb.generateNewShare();

      const expectLatestResult = await tb.catchupToLatestShare({
        shareStore: spShareStore,
        includeLocalMetadataTransitions: true,
      });

      const latestSPShareStore = tb.outputShareStore(1n);

      expect(JSON.stringify(latestSPShareStore.toJSON())).toBe(JSON.stringify(expectLatestResult.latestShare.toJSON()));
      expect(JSON.stringify(tb.metadata.toJSON())).toBe(JSON.stringify(expectLatestResult.shareMetadata.toJSON()));
    });

    it("should able to initialize and reconstruct with localMetadataTransision", async function () {
      const tb = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: true,
        storageLayer: customSL,
      });

      await initializeNewKey(tb);

      await tb.reconstructKey(true);

      const newShareMap = await tb.generateNewShare();
      const newShare = newShareMap.newShareStores[newShareMap.newShareIndex.toString(16)];

      const localMetadataTransistionShare = tb._localMetadataTransitions[0];
      const localMetadataTransistionData = tb._localMetadataTransitions[1];

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
      });

      const newMetadata = Metadata.fromJSON(tb.metadata.toJSON());
      await tb2.initialize({
        neverInitializeNewKey: true,
        transitionMetadata: newMetadata,
        // previouslyFetchedCloudMetadata: tempCloud,
        previousLocalMetadataTransitions: [localMetadataTransistionShare, localMetadataTransistionData],
        // withShare: shareToUseForSerialization,
      });

      await tb2.inputShareStoreSafe(newShare);
      await tb2.reconstructKey();

      expect(tb.secp256k1Key.toString(16)).toBe(tb2.secp256k1Key.toString(16));
    });
  });

  describe("Lock", function () {
    it(`#locks should fail when tkey/nonce is updated, manualSync=${mode}`, async function () {
      const tb = new ThresholdKey({ serviceProvider: customSP, manualSync: mode, storageLayer: customSL });
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, manualSync: mode, storageLayer: customSL });
      await tb2.initialize();
      tb2.inputShareStore(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
      await tb2.generateNewShare();
      await tb2.syncLocalMetadataTransitions();

      await expect(
        (async () => {
          await tb.generateNewShare();
          await tb.syncLocalMetadataTransitions();
        })()
      ).rejects.toMatchObject({ code: 1401 });
    });

    it(`#locks should not allow for writes of the same nonce, manualSync=${mode}`, async function () {
      const tb = new ThresholdKey({ serviceProvider: customSP, manualSync: mode, storageLayer: customSL });
      const resp1 = await initializeNewKey(tb, { initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, manualSync: mode, storageLayer: customSL });
      await tb2.initialize();
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      expect(resp1.secp256k1Key).toBe(reconstructedKey.secp256k1Key);
      const alltbs: InstanceType<typeof ThresholdKey>[] = [];
      // make moar tbs
      for (let i = 0; i < 5; i += 1) {
        const temp = new ThresholdKey({ serviceProvider: customSP, manualSync: mode, storageLayer: customSL });
        await temp.initialize();
        await temp.inputShareStoreSafe(resp1.deviceShare);
        await temp.reconstructKey();
        alltbs.push(temp);
      }
      // generate shares
      const promises = [];
      for (let i = 0; i < alltbs.length; i += 1) {
        promises.push(alltbs[i].generateNewShare().then((_) => alltbs[i].syncLocalMetadataTransitions()));
      }
      const res = await Promise.allSettled(promises);

      let count = 0;
      for (let i = 0; i < res.length; i += 1) {
        if (res[i].status === "fulfilled") count += 1;
      }
      expect(count).toBe(1);
    });
  });

  describe("tkey error cases", function () {
    let tb: InstanceType<typeof ThresholdKey>;
    let resp1: Awaited<ReturnType<typeof initializeNewKey>>;

    beforeAll(async function () {
      tb = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      resp1 = await initializeNewKey(tb, { initializeModules: true });
      await tb.syncLocalMetadataTransitions();
    });

    afterEach(function () {
      vi.restoreAllMocks();
    });

    it(`#should throw error code 1101 if metadata is undefined, in manualSync: ${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await expect(
        (async () => {
          await tb2.reconstructKey();
        })()
      ).rejects.toMatchObject({ code: 1101 });
      await expect(
        (async () => {
          tb2.getMetadata();
        })()
      ).rejects.toMatchObject({ code: 1101 });
      await expect(
        (async () => {
          await tb2.deleteShare(undefined as unknown as bigint);
        })()
      ).rejects.toMatchObject({ code: 1101 });
      await expect(
        (async () => {
          await tb2.generateNewShare();
        })()
      ).rejects.toMatchObject({ code: 1101 });
      const exportedSeedShare = await tb.outputShare(resp1.deviceShare.share.shareIndex, "mnemonic");
      await expect(
        (async () => {
          await tb2.inputShare(exportedSeedShare, "mnemonic");
        })()
      ).rejects.toMatchObject({ code: 1101 });
    });

    it(`#should throw error code 1301 if privKey is not available, in manualSync: ${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ neverInitializeNewKey: true });
      await expect(
        (async () => {
          await tb2.generateNewShare();
        })()
      ).rejects.toMatchObject({ code: 1301 });
      await expect(
        (async () => {
          await tb2.deleteShare(undefined as unknown as bigint);
        })()
      ).rejects.toMatchObject({ code: 1301 });
      await expect(
        (async () => {
          await tb2.encrypt(utf8ToBytes("test data"));
        })()
      ).rejects.toMatchObject({ code: 1301 });
    });

    it(`#should throw error code 1302 if not enough shares are avaible for reconstruction, in manualSync: ${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ neverInitializeNewKey: true });
      await expect(
        (async () => {
          await tb2.reconstructKey();
        })()
      ).rejects.toMatchObject({ code: 1302 });
    });

    it(`#should throw error code 1102 if metadata get failed, in manualSync: ${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      vi.spyOn(tb2.storageLayer, "getMetadata").mockRejectedValue(new Error("failed to fetch metadata"));
      await expect(
        (async () => {
          await tb2.initialize({ neverInitializeNewKey: true });
        })()
      ).rejects.toMatchObject({ code: 1102 });
    });

    it(`#should throw error code 1103 if metadata post failed, in manualSync: ${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ neverInitializeNewKey: true });
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      await tb2.reconstructKey();
      await tb2.syncLocalMetadataTransitions();
      vi.spyOn(tb2.storageLayer, "setMetadataStream").mockRejectedValue(new Error("failed to set metadata"));
      if (mode) {
        await expect(
          (async () => {
            await tb2.addShareDescription(resp1.deviceShare.share.shareIndex.toString(16), JSON.stringify({ test: "unit test" }), true);
            await tb2.syncLocalMetadataTransitions();
          })()
        ).rejects.toMatchObject({ code: 1103 });
      } else {
        await expect(
          (async () => {
            await tb2.addShareDescription(resp1.deviceShare.share.shareIndex.toString(16), JSON.stringify({ test: "unit test" }), true);
          })()
        ).rejects.toMatchObject({ code: 1103 });
      }
    });
  });

  describe("OneKey", function () {
    if (!mode || isMocked) {
      it.skip("OneKey tests require manualSync and non-mocked", () => {});
      return;
    }

    it("should be able to init tkey with 1 out of 1", async function () {
      const postboxKeyBN = bytesToNumberBE(generatePrivate());
      const pubKeyPoint = getPubKeyPoint(postboxKeyBN);
      const metadataNonce = bytesToNumberBE(generatePrivate());

      const serviceProvider = new TorusServiceProvider({
        postboxKey: postboxKeyBN.toString(16),
        customAuthArgs: {
          enableOneKey: true,
          metadataUrl: getMetadataUrl(),
          // This url has no effect as postbox key is passed, passing it just to satisfy direct auth checks.
          baseUrl: "http://localhost:3000",
          web3AuthClientId: "test",
          network: "sapphire_devnet",
        },
      });
      const storageLayer2 = new TorusStorageLayer({ hostUrl: getMetadataUrl() });

      const nonceRes = await getOrSetNonce(
        getMetadataUrl(),
        serviceProvider.customAuthInstance.torus.ec,
        0,
        pubKeyPoint.x.toString(16),
        pubKeyPoint.y.toString(16),
        postboxKeyBN,
        false,
        false,
        metadataNonce
      );

      const nonceResTyped = nonceRes as { typeOfUser?: string; nonce?: string; pubNonce: { x: string; y: string }; upgraded: boolean };
      if (nonceResTyped.typeOfUser) {
        expect(nonceResTyped.typeOfUser).toBe("v2");
      }
      const { nonce, pubNonce, upgraded: isUpgraded } = nonceResTyped;
      expect(nonce).not.toBe(undefined);
      expect(pubNonce).not.toBe(undefined);
      expect(isUpgraded).toBe(false);

      const nonceBN = hexToBigInt(nonce);
      const importKey = ((postboxKeyBN + nonceBN) % secp256k1.Point.CURVE().n).toString(16);

      const tKey = new ThresholdKey({ serviceProvider, storageLayer: storageLayer2, manualSync: mode });
      await tKey.initialize({
        importKey: hexToBigInt(importKey),
        delete1OutOf1: true,
      });
      await tKey.syncLocalMetadataTransitions();
      expect(tKey.secp256k1Key.toString(16)).toBe(importKey);

      const nonceRes2 = await getOrSetNonce(
        getMetadataUrl(),
        serviceProvider.customAuthInstance.torus.ec,
        0,
        pubKeyPoint.x.toString(16),
        pubKeyPoint.y.toString(16),
        postboxKeyBN,
        true, // passing nonce again should not have any effect as getOnly param is true
        false,
        metadataNonce
      );
      const nonceRes2Typed = nonceRes2 as { typeOfUser?: string; nonce?: string; pubNonce: { x: string; y: string }; upgraded: boolean };
      if (nonceRes2Typed.typeOfUser) {
        expect(nonceRes2Typed.typeOfUser).toBe("v2");
      }
      const { nonce: newNonce, pubNonce: newPubNonce, upgraded } = nonceRes2Typed;
      expect(upgraded).toBe(true);
      expect(newNonce).toBe(undefined);
      expect(pubNonce).toStrictEqual(newPubNonce);
    });

    it("should not change v1 address without a custom nonce when getOrSetNonce is called", async function () {
      // Create an existing v1 account
      const postboxKeyBN = bytesToNumberBE(generatePrivate());
      const pubKeyPoint = getPubKeyPoint(postboxKeyBN);

      // This test require development API, only work with local/beta env
      let metadataUrl = getMetadataUrl();
      if (metadataUrl === "https://metadata.web3auth.io" || metadataURL.indexOf("node.web3auth.io") > -1)
        metadataUrl = "https://metadata-testing.tor.us";
      await post(
        `${metadataUrl}/set_nonce`,
        {
          pub_key_X: pubKeyPoint.x.toString(16),
          pub_key_Y: pubKeyPoint.y.toString(16),
        },
        undefined,
        { useAPIKey: true }
      );

      // Call get or set nonce
      const serviceProvider = new TorusServiceProvider({
        postboxKey: postboxKeyBN.toString(16),
        customAuthArgs: {
          enableOneKey: true,
          metadataUrl,
          // This url has no effect as postbox key is passed, passing it just to satisfy direct auth checks.
          baseUrl: "http://localhost:3000",
          web3AuthClientId: "test",
          network: "mainnet",
        },
      });

      const res = await getOrSetNonce(
        metadataUrl,
        serviceProvider.customAuthInstance.torus.ec,
        0,
        pubKeyPoint.x.toString(16),
        pubKeyPoint.y.toString(16),
        postboxKeyBN
      );
      expect(res.typeOfUser).toBe("v1");

      const anotherRes = await getOrSetNonce(
        metadataUrl,
        serviceProvider.customAuthInstance.torus.ec,
        0,
        pubKeyPoint.x.toString(16),
        pubKeyPoint.y.toString(16),
        postboxKeyBN
      );
      expect(res).toStrictEqual(anotherRes);
    });
  });

  ed25519Tests({ manualSync: mode, torusSP: customSP as TorusServiceProvider, storageLayer: customSL as TorusStorageLayer });
};
