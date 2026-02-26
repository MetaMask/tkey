/* eslint-disable @typescript-eslint/no-shadow */
/* eslint-disable mocha/no-exports */
/* eslint-disable import/no-extraneous-dependencies */

import { getPubKeyPoint, KEY_NOT_FOUND, secp256k1, SHARE_DELETED, ShareStore } from "@tkey/common-types";
import { Metadata } from "@tkey/core";
import { ED25519Format, PrivateKeyModule, SECP256K1Format } from "@tkey/private-keys";
import { SecurityQuestionsModule } from "@tkey/security-questions";
import { MetamaskSeedPhraseFormat, SeedPhraseModule } from "@tkey/seed-phrase";
import { TorusServiceProvider } from "@tkey/service-provider-torus";
import { ShareTransferModule } from "@tkey/share-transfer";
import { TorusStorageLayer } from "@tkey/storage-layer-torus";
import { generatePrivate } from "@toruslabs/eccrypto";
import { post } from "@toruslabs/http-helpers";
import { bytesToHex, utf8ToBytes } from "@toruslabs/metadata-helpers";
import { getOrSetNonce, keccak256 } from "@toruslabs/torus.js";
import { deepEqual, deepStrictEqual, equal, fail, notEqual, notStrictEqual, strict, strictEqual, throws } from "assert";
import { bytesToNumberBE } from "@noble/curves/utils.js";
import { JsonRpcProvider } from "ethers";
import { createSandbox } from "sinon";

import { TKeyDefault as ThresholdKey } from "../src/index";
import { ed25519Tests } from "./ed25519/ed25519";
import { getMetadataUrl, getServiceProvider, initStorageLayer, isMocked } from "./helpers";

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

const metadataURL = getMetadataUrl();

function getTempKey() {
  return bytesToHex(generatePrivate());
}
function compareBigintArray(a, b, message) {
  if (a.length !== b.length) throw new Error(message);
  return a.map((el) => {
    const found = b.find((pl) => pl === el);
    if (found === undefined) throw new Error(message);
    return 0;
  });
}

function compareReconstructedKeys(a, b, message) {
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

export const sharedTestCases = (mode, torusSP, storageLayer) => {
  const customSP = torusSP;
  const customSL = storageLayer;

  describe("tkey", function () {
    let tb;

    beforeEach("Setup ThresholdKey", async function () {
      tb = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
    });

    it("#should be able to initializeNewKey using initialize and reconstruct it", async function () {
      const sp = customSP;
      sp.postboxKey = BigInt(`0x${getTempKey()}`);
      const storageLayer = initStorageLayer({ hostUrl: metadataURL });
      const tb2 = new ThresholdKey({ serviceProvider: sp, storageLayer, manualSync: mode });
      await tb2.initialize();
      const reconstructedKey = await tb2.reconstructKey();
      await tb2.syncLocalMetadataTransitions();
      if (tb2.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to reconstruct key when initializing a key, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ neverInitializeNewKey: true });
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to reconstruct key when initializing with user input, manualSync=${mode}`, async function () {
      let determinedShare = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      determinedShare = determinedShare % secp256k1.CURVE.n;
      const resp1 = await tb._initializeNewKey({ determinedShare, initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize();
      await tb2.inputShareStoreSafe(resp1.userShare);
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to reconstruct key when initializing with service provider, manualSync=${mode}`, async function () {
      const importedKey = bytesToNumberBE(generatePrivate());
      const resp1 = await tb._initializeNewKey({ importedKey, initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize();
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      if (importedKey !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to reconstruct key when initializing a with a share, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.CURVE.n;
      const resp1 = await tb._initializeNewKey({ userInput, initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ withShare: resp1.userShare });
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to reconstruct key after refresh and initializing with a share, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.CURVE.n;
      const resp1 = await tb._initializeNewKey({ userInput, initializeModules: true });
      const newShares = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ withShare: resp1.userShare });
      await tb2.inputShareStoreSafe(newShares.newShareStores[newShares.newShareIndex.toString(16)]);
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to reconstruct key after refresh and initializing with service provider, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.CURVE.n;
      const resp1 = await tb._initializeNewKey({ userInput, initializeModules: true });
      const newShares = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize();
      await tb2.inputShareStoreSafe(newShares.newShareStores[newShares.newShareIndex.toString(16)]);
      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to reconstruct key, even with old metadata, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize(); // initialize sdk with old metadata

      await tb.generateNewShare(); // generate new share to update metadata
      await tb.syncLocalMetadataTransitions();

      await tb2.inputShareStoreSafe(resp1.deviceShare, true);
      const reconstructedKey = await tb2.reconstructKey(); // reconstruct key with old metadata should work to poly
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to not create a new key if initialize is called with neverInitializeNewKey, manualSync=${mode}`, async function () {
      const newSP = getServiceProvider({ type: torusSP.serviceProviderName });
      const tb2 = new ThresholdKey({ serviceProvider: newSP, storageLayer: customSL });
      await rejects(async () => {
        await tb2.initialize({ neverInitializeNewKey: true });
      }, Error);
    });

    it(`#should be able to output unavailable share store, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      const { newShareStores, newShareIndex } = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ neverInitializeNewKey: true });
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      const shareStore = tb2.outputShareStore(newShareIndex);
      strictEqual(newShareStores[newShareIndex.toString(16)].share.share.toString(16), shareStore.share.share.toString(16));

      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to insert shares from existing tkey using _initializeNewKey, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      const { newShareStores: tbShareStore, newShareIndex: tbShareIndex } = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const tb3 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });

      await tb3.initialize({ neverInitializeNewKey: true });
      try {
        await tb3.inputShareStoreSafe(resp1.deviceShare, true);
      } catch (err) {
        throw new Error(err);
      }
      const reconstructedKey = await tb3.reconstructKey();

      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
      const shareStore = tb3.outputShareStore(tbShareIndex);
      strictEqual(tbShareStore[tbShareIndex.toString(16)].share.share.toString(16), shareStore.share.share.toString(16));
    });

    it(`#should be able to insert shares from existing tkey using new TKey Instance, manualSync=${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      const resp2 = await tb2._initializeNewKey({ initializeModules: true });
      await tb2.syncLocalMetadataTransitions();

      const tb3 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });

      await tb3.initialize({ neverInitializeNewKey: true });
      await tb3.inputShareStoreSafe(resp2.deviceShare, true);
      const reconstructedKey = await tb3.reconstructKey();
      if (resp2.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#shouldn't be able to insert shares from random threshold key, manualSync=${mode}`, async function () {
      // wrong tkey instance
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      const { newShareStores: tbShareStore, newShareIndex: tbShareIndex } = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      // tkey instance with correct share stores and index
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      const resp2 = await tb2._initializeNewKey({ initializeModules: true });
      await tb2.syncLocalMetadataTransitions();

      const tb3 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb3.initialize({ neverInitializeNewKey: true });
      await tb3.syncLocalMetadataTransitions();

      // throws since share doesn't
      await rejects(
        async () => {
          await tb3.inputShareStoreSafe(tbShareStore[tbShareIndex.toString(16)], true);
        },
        (err) => {
          strictEqual(err.code, 1307, "CoreError: Share doesn't exist");
          return true;
        }
      );
      await rejects(
        async () => {
          await tb3.inputShareStoreSafe(resp1.deviceShare, true);
        },
        (err) => {
          strictEqual(err.code, 1307, "CoreError: Share doesn't exist");
          return true;
        }
      );
      // should be able to insert if correct share store and index
      await tb3.inputShareStoreSafe(resp2.deviceShare, true);
      await tb3.reconstructKey();
      const { newShareStores: tb3ShareStore, newShareIndex: tb3ShareIndex } = await tb3.generateNewShare();
      await tb3.syncLocalMetadataTransitions();
      await tb3.reconstructKey();

      await tb2.inputShareStoreSafe(tb3ShareStore[tb3ShareIndex.toString(16)], true);
      const reconstructedKey2 = await tb2.reconstructKey();
      if (resp2.secp256k1Key !== reconstructedKey2.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to update metadata, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
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
      await rejects(async () => {
        await tb2.generateNewShare();
        await tb2.syncLocalMetadataTransitions();
      }, Error);

      // try creating again
      const newtb = await tb2.updateSDK();
      await newtb.reconstructKey();
      await newtb.generateNewShare();
      await newtb.syncLocalMetadataTransitions();
    });
  });

  describe(`tkey share deletion, manualSync=${mode}`, function () {
    let deletedShareIndex;
    let deletedShareStores;
    let shareStoreAfterDelete;
    let tb;
    let tbInitResp;

    before(`#should be able to generate and delete a share, manualSync=${mode}`, async function () {
      tb = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      tbInitResp = await tb._initializeNewKey({ initializeModules: true });
      const newShare = await tb.generateNewShare();
      const updatedShareStore = await tb.deleteShare(newShare.newShareIndex);
      deletedShareIndex = newShare.newShareIndex;
      deletedShareStores = newShare.newShareStores;
      shareStoreAfterDelete = updatedShareStore.newShareStores;
      await tb.syncLocalMetadataTransitions();
    });

    it(`#should be not be able to lookup delete share, manualSync=${mode}`, async function () {
      const newKeys = Object.keys(shareStoreAfterDelete);
      if (newKeys.find((el) => el === deletedShareIndex.toString(16))) {
        fail("Unable to delete share index");
      }
    });

    it(`#should not be able to delete more than threshold number of shares, manualSync=${mode}`, async function () {
      const { newShareIndex: newShareIndex1 } = await tb.generateNewShare();
      await tb.deleteShare(newShareIndex1);
      await tb.syncLocalMetadataTransitions();
      await rejects(async () => {
        await tb.deleteShare(tbInitResp.deviceShare.share.shareIndex);
      }, Error);
    });

    it(`#should not be able to initialize with a deleted share, manualSync=${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await rejects(async function () {
        await tb2.initialize({ withShare: deletedShareStores[deletedShareIndex.toString(16)] });
      });
    });

    it(`#should not be able to add share post deletion, manualSync=${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize();
      await rejects(async () => {
        await tb2.inputShare(deletedShareStores[deletedShareIndex.toString(16)].share.share);
      }, Error);
    });

    it(`#should be able to delete a user, manualSync=${mode}`, async function () {
      // create 2/4
      await tb._initializeNewKey({ initializeModules: true });
      await tb.generateNewShare();
      const shareStoresAtEpoch2 = tb.getAllShareStoresForLatestPolynomial();

      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();
      const sharesStoresAtEpoch3 = tb.getAllShareStoresForLatestPolynomial();
      await tb.CRITICAL_deleteTkey();

      const spData = await customSL.getMetadata({ serviceProvider: customSP });
      const data2 = await Promise.allSettled(shareStoresAtEpoch2.map((x) => tb.catchupToLatestShare({ shareStore: x })));
      const data3 = await Promise.all(sharesStoresAtEpoch3.map((x) => customSL.getMetadata({ privKey: x.share.share })));

      deepStrictEqual(spData.message, KEY_NOT_FOUND);

      data2.forEach((x) => {
        deepStrictEqual(x.status, "rejected");
        deepStrictEqual(x.reason.code, 1308);
      });

      data3.forEach((x) => {
        deepStrictEqual(x.message, SHARE_DELETED);
      });
    });

    it(`#should be able to reinitialize after wipe, manualSync=${mode}`, async function () {
      // create 2/4
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
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
      notEqual(data3.message, KEY_NOT_FOUND);
      deepStrictEqual(tb2.metadata.nonce, 1);

      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.secp256k1Key === reconstructedKey.secp256k1Key) {
        fail("key should be different");
      }
    });
  });

  describe("tkey serialization/deserialization", function () {
    let tb;

    beforeEach("Setup ThresholdKey", async function () {
      tb = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
    });

    it(`#should serialize and deserialize correctly without tkeyArgs, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.CURVE.n;
      const resp1 = await tb._initializeNewKey({ userInput, initializeModules: true });
      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const stringified = JSON.stringify(tb);
      const tb3 = await ThresholdKey.fromJSON(JSON.parse(stringified));
      const finalKey = await tb3.reconstructKey();
      strictEqual(finalKey.secp256k1Key.toString(16), resp1.secp256k1Key.toString(16), "Incorrect serialization");
    });

    it(`#should serialize and deserialize correctly with tkeyArgs, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.CURVE.n;
      const resp1 = await tb._initializeNewKey({ userInput, initializeModules: true });
      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const stringified = JSON.stringify(tb);
      const tb3 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: customSP, storageLayer: customSL });
      const finalKey = await tb3.reconstructKey();
      strictEqual(finalKey.secp256k1Key.toString(16), resp1.secp256k1Key.toString(16), "Incorrect serialization");
    });

    it(`#should serialize and deserialize correctly, keeping localTransitions consistent before syncing NewKeyAssign, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.CURVE.n;
      const resp1 = await tb._initializeNewKey({ userInput, initializeModules: true });

      // generate and delete
      const { newShareIndex: shareIndex1 } = await tb.generateNewShare();
      await tb.deleteShare(shareIndex1);

      const { newShareStores: shareStores, newShareIndex: shareIndex } = await tb.generateNewShare();

      const stringified = JSON.stringify(tb);
      const tb2 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: customSP, storageLayer: customSL });
      if (tb2.manualSync !== mode) {
        fail(`manualSync should be ${mode}`);
      }
      const finalKey = await tb2.reconstructKey();
      const shareToVerify = tb2.outputShareStore(shareIndex);
      strictEqual(shareStores[shareIndex.toString(16)].share.share.toString(16), shareToVerify.share.share.toString(16));
      await tb2.syncLocalMetadataTransitions();
      strictEqual(finalKey.secp256k1Key.toString(16), resp1.secp256k1Key.toString(16), "Incorrect serialization");

      const reconstructedKey2 = await tb2.reconstructKey();
      if (resp1.secp256k1Key !== reconstructedKey2.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should serialize and deserialize correctly keeping localTransitions afterNewKeyAssign, manualSync=${mode}`, async function () {
      let userInput = BigInt(keccak256(utf8ToBytes("user answer blublu")));
      userInput = userInput % secp256k1.CURVE.n;
      const resp1 = await tb._initializeNewKey({ userInput, initializeModules: true });
      await tb.syncLocalMetadataTransitions();
      const reconstructedKey = await tb.reconstructKey();
      const { newShareStores: shareStores, newShareIndex: shareIndex } = await tb.generateNewShare();

      const stringified = JSON.stringify(tb);
      const tb2 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: customSP, storageLayer: customSL });
      const finalKey = await tb2.reconstructKey();
      const shareToVerify = tb2.outputShareStore(shareIndex);
      strictEqual(shareStores[shareIndex.toString(16)].share.share.toString(16), shareToVerify.share.share.toString(16));
      await tb2.syncLocalMetadataTransitions();
      strictEqual(finalKey.secp256k1Key.toString(16), reconstructedKey.secp256k1Key.toString(16), "Incorrect serialization");

      const reconstructedKey2 = await tb2.reconstructKey();
      if (resp1.secp256k1Key !== reconstructedKey2.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to reshare a key and retrieve from service provider serialization, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      const { newShareStores, newShareIndex } = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();
      const tb3 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb3.initialize();
      await tb3.inputShareStoreSafe(newShareStores[newShareIndex.toString(16)]);

      const stringified = JSON.stringify(tb3);
      const tb4 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      const finalKeyPostSerialization = await tb4.reconstructKey();
      strictEqual(finalKeyPostSerialization.secp256k1Key.toString(16), resp1.secp256k1Key.toString(16), "Incorrect serialization");
    });

    it(`#should be able to serialize and deserialize without service provider share or the postbox key, manualSync=${mode}`, async function () {
      const customSP2 = getServiceProvider({ type: torusSP.serviceProviderName });
      const customSL2 = initStorageLayer({ hostUrl: metadataURL });
      const tb = new ThresholdKey({ serviceProvider: customSP2, storageLayer: customSL2, manualSync: mode });
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      const { newShareStores: newShareStores1, newShareIndex: newShareIndex1 } = await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      const customSP3 = getServiceProvider({ type: torusSP.serviceProviderName, isEmptyProvider: true });
      customSL2.serviceProvider = customSP3;
      const tb2 = new ThresholdKey({ serviceProvider: customSP3, storageLayer: customSL2, manualSync: mode });
      await tb2.initialize({ withShare: resp1.deviceShare });
      await tb2.inputShareStoreSafe(newShareStores1[newShareIndex1.toString(16)]);
      await tb2.reconstructKey();
      const stringified = JSON.stringify(tb2);

      const tb3 = await ThresholdKey.fromJSON(JSON.parse(stringified));
      const tb3Key = await tb3.reconstructKey();
      strictEqual(tb3Key.secp256k1Key.toString(16), resp1.secp256k1Key.toString(16), "Incorrect serialization");
    });

    it(`#should not be able to updateSDK with newKeyAssign transitions unsynced, manualSync=${mode}`, async function () {
      await tb._initializeNewKey({ initializeModules: true });
      const stringified = JSON.stringify(tb);
      const tb2 = await ThresholdKey.fromJSON(JSON.parse(stringified), {});

      if (mode) {
        // Can't updateSDK, please do key assign.
        await rejects(async function () {
          await tb2.updateSDK();
        }, Error);
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
      deepStrictEqual(resp, message, "set and get message should be equal");
    });

    it(`#should get or set with specified private key correctly, manualSync=${mode}`, async function () {
      const privKey = generatePrivate().toString(16);
      const privKeyBN = BigInt(`0x${privKey}`);
      const storageLayer = initStorageLayer({ hostUrl: metadataURL });
      const message = { test: Math.random().toString(36).substring(7) };
      await storageLayer.setMetadata({ input: message, privKey: privKeyBN });
      const resp = await storageLayer.getMetadata({ privKey: privKeyBN });
      deepStrictEqual(resp, message, "set and get message should be equal");
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
        deepStrictEqual(responses[i], messages[i], "set and get message should be equal");
      }
    });
  });

  describe("SecurityQuestionsModule", function () {
    let tb;

    beforeEach("initialize security questions module", async function () {
      tb = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
        manualSync: mode,
      });
    });

    it(`#should be able to reconstruct key and initialize a key with security questions, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      await rejects(async function () {
        await tb.modules.securityQuestions.inputShareFromSecurityQuestions("blublu");
      }, Error);

      await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
      await tb.syncLocalMetadataTransitions();
      const question = tb.modules.securityQuestions.getSecurityQuestions();
      strictEqual(question, "who is your cat?");
      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb2.initialize();

      // wrong password
      await rejects(async function () {
        await tb.modules.securityQuestions.inputShareFromSecurityQuestions("blublu-wrong");
      }, Error);

      await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("blublu");
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to delete and add security questions, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      // delete sq
      const sqIndex = tb.metadata.generalStore.securityQuestions.shareIndex;
      await tb.deleteShare(sqIndex);

      // add sq again
      await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blubluss", "who is your cat?");
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb2.initialize();

      await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("blubluss");
      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to reconstruct key and initialize a key with security questions after refresh, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb.generateNewShare();
      await tb.syncLocalMetadataTransitions();

      await tb2.initialize();

      await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("blublu");
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to change password, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });

      // should throw
      await rejects(async function () {
        await tb.modules.securityQuestions.changeSecurityQuestionAndAnswer("dodo", "who is your cat?");
      }, Error);

      await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
      await tb.modules.securityQuestions.changeSecurityQuestionAndAnswer("dodo", "who is your cat?");
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb2.initialize();

      await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("dodo");
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to change password and serialize, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
      await tb.modules.securityQuestions.changeSecurityQuestionAndAnswer("dodo", "who is your cat?");
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb2.initialize();

      await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("dodo");
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }

      const stringified = JSON.stringify(tb2);
      const tb3 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: customSP, storageLayer: customSL });
      const finalKeyPostSerialization = await tb3.reconstructKey();
      strictEqual(finalKeyPostSerialization.toString(16), reconstructedKey.toString(16), "Incorrect serialization");
    });

    it(`#should be able to get answers, even when they change, manualSync=${mode}`, async function () {
      tb = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule(true) },
      });
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      const qn = "who is your cat?";
      const ans1 = "blublu";
      const ans2 = "dodo";
      await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions(ans1, qn);
      let gotAnswer = await tb.modules.securityQuestions.getAnswer();
      if (gotAnswer !== ans1) {
        fail("answers should be the same");
      }
      await tb.modules.securityQuestions.changeSecurityQuestionAndAnswer(ans2, qn);
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        storageLayer: customSL,
        modules: { securityQuestions: new SecurityQuestionsModule(true) },
      });
      await tb2.initialize();

      await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("dodo");
      const reconstructedKey = await tb2.reconstructKey();
      // compareBNArray(resp1.secp256k1Key, reconstructedKey, "key should be able to be reconstructed");
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }

      gotAnswer = await tb2.modules.securityQuestions.getAnswer();
      if (gotAnswer !== ans2) {
        fail("answers should be the same");
      }
    });
  });

  describe("ShareTransferModule", function () {
    let tb;

    beforeEach("Setup ThresholdKey", async function () {
      tb = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
        modules: { shareTransfer: new ShareTransferModule() },
      });
    });

    it(`#should be able to transfer share via the module, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
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
      const pubkey = await tb2.modules.shareTransfer.requestNewShare();

      await tb.modules.shareTransfer.approveRequest(pubkey, result.newShareStores[result.newShareIndex.toString(16)]);
      await tb.syncLocalMetadataTransitions();

      await tb2.modules.shareTransfer.startRequestStatusCheck(pubkey);

      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to change share transfer pointer after share deletion, manualSync=${mode}`, async function () {
      await tb._initializeNewKey({ initializeModules: true });
      const firstShareTransferPointer = tb.metadata.generalStore.shareTransfer.pointer.toString(16);
      const { newShareIndex: newShareIndex1 } = await tb.generateNewShare();
      const secondShareTransferPointer = tb.metadata.generalStore.shareTransfer.pointer.toString(16);

      strictEqual(firstShareTransferPointer, secondShareTransferPointer);

      await tb.syncLocalMetadataTransitions();
      await tb.deleteShare(newShareIndex1);
      const thirdShareTransferPointer = tb.metadata.generalStore.shareTransfer.pointer.toString(16);

      notStrictEqual(secondShareTransferPointer, thirdShareTransferPointer);
      await tb.syncLocalMetadataTransitions();
    });

    it(`#should be able to transfer device share, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
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
      const pubkey = await tb2.modules.shareTransfer.requestNewShare("unit test", currentShareIndexes);

      const requests = await tb.modules.shareTransfer.getShareTransferStore();
      const pubkey2 = Object.keys(requests)[0];
      await tb.modules.shareTransfer.approveRequest(pubkey2);

      await tb2.modules.shareTransfer.startRequestStatusCheck(pubkey, true);

      // await new Promise((res) => {
      //   setTimeout(res, 1001);
      // });

      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });

    it(`#should be able to delete share transfer from another device, manualSync=${mode}`, async function () {
      await tb._initializeNewKey({ initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
        modules: { shareTransfer: new ShareTransferModule() },
      });
      await tb2.initialize();

      // usually should be called in callback, but mocha does not allow
      const encKey2 = await tb2.modules.shareTransfer.requestNewShare();
      await tb.modules.shareTransfer.deleteShareTransferStore(encKey2); // delete 1st request from 2nd
      const newRequests = await tb2.modules.shareTransfer.getShareTransferStore();
      if (encKey2 in newRequests) {
        fail("Unable to delete share transfer request");
      }
    });

    it(`#should be able to reset share transfer store, manualSync=${mode}`, async function () {
      await tb._initializeNewKey({ initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      await tb.modules.shareTransfer.resetShareTransferStore();
      const stStore = await tb.modules.shareTransfer.getShareTransferStore();
      if (stStore.message !== KEY_NOT_FOUND) {
        fail("Unable to reset share store");
      }
    });
  });

  describe("ShareSerializationModule", function () {
    it(`#should be able to serialize and deserialize share, manualSync=${mode}`, async function () {
      const tb = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
      });
      const resp1 = await tb._initializeNewKey({ initializeModules: true });

      // should throw
      await rejects(async function () {
        await tb.outputShare(resp1.deviceShare.share.shareIndex, "mnemonic-49");
      });

      const exportedSeedShare = await tb.outputShare(resp1.deviceShare.share.shareIndex, "mnemonic");
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
      });
      await tb2.initialize();

      // should throw
      await rejects(async function () {
        await tb2.inputShare(exportedSeedShare.toString(16), "mnemonic-49");
      });

      await tb2.inputShare(exportedSeedShare.toString(16), "mnemonic");
      const reconstructedKey = await tb2.reconstructKey();

      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
    });
  });

  describe("TkeyStore", function () {
    let tb;
    let metamaskSeedPhraseFormat;
    let secp256k1Format;
    let ed25519privateKeyFormat;

    beforeEach("Setup ThresholdKey", async function () {
      metamaskSeedPhraseFormat = new MetamaskSeedPhraseFormat(new JsonRpcProvider("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68"));
      secp256k1Format = new SECP256K1Format();
      ed25519privateKeyFormat = new ED25519Format();
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
      await tb2._initializeNewKey({ initializeModules: true });
      // should throw
      await rejects(async () => {
        await tb2.modules.seedPhrase.setSeedPhrase("HD Key Tree", seedPhraseToSet);
      }, Error);

      await rejects(async () => {
        await tb2.modules.seedPhrase.setSeedPhrase("HD Key Tree", `${seedPhraseToSet}123`);
      }, Error);

      // should throw
      await rejects(async () => {
        const actualPrivateKeys = [BigInt("0x4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390")];
        await tb2.modules.privateKeyModule.setPrivateKey("secp256k1n", actualPrivateKeys[0].toString(16));
      }, Error);

      await rejects(async () => {
        const actualPrivateKeys = [BigInt("0x4bd0041a9b16a7268a5de7982f2422b15635c4fd170c140dc48976wqerwer0")];
        await tb2.modules.privateKeyModule.setPrivateKey("secp256k1n", actualPrivateKeys[0].toString(16));
      }, Error);
    });

    it(`#should get/set multiple seed phrase, manualSync=${mode}`, async function () {
      const seedPhraseToSet = "seed sock milk update focus rotate barely fade car face mechanic mercy";
      const seedPhraseToSet2 = "object brass success calm lizard science syrup planet exercise parade honey impulse";
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      await tb.modules.seedPhrase.setSeedPhrase("HD Key Tree", seedPhraseToSet);
      await tb.modules.seedPhrase.setSeedPhrase("HD Key Tree", seedPhraseToSet2);
      await tb.syncLocalMetadataTransitions();
      const returnedSeed = await tb.modules.seedPhrase.getSeedPhrases();
      strictEqual(returnedSeed[0].seedPhrase, seedPhraseToSet);
      strictEqual(returnedSeed[1].seedPhrase, seedPhraseToSet2);

      const metamaskSeedPhraseFormat2 = new MetamaskSeedPhraseFormat(
        new JsonRpcProvider("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68")
      );
      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
        modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat2]) },
      });
      await tb2.initialize();
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstuctedKey = await tb2.reconstructKey();
      await tb.modules.seedPhrase.getSeedPhrasesWithAccounts();

      compareReconstructedKeys(reconstuctedKey, {
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
      await tb._initializeNewKey({ initializeModules: true });
      await tb.modules.seedPhrase.setSeedPhrase("HD Key Tree", seedPhraseToSet);
      await tb.syncLocalMetadataTransitions();

      const actualPrivateKeys = [BigInt("0x70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46")];
      const derivedKeys = await tb.modules.seedPhrase.getAccounts();
      compareBigintArray(actualPrivateKeys, derivedKeys, "key should be same");
    });

    it(`#should be able to generate seed phrase if not given, manualSync=${mode}`, async function () {
      await tb._initializeNewKey({ initializeModules: true });
      await tb.modules.seedPhrase.setSeedPhrase("HD Key Tree");
      await tb.syncLocalMetadataTransitions();

      const [seed] = await tb.modules.seedPhrase.getSeedPhrases();
      const derivedKeys = await tb.modules.seedPhrase.getAccounts();
      strict(metamaskSeedPhraseFormat.validateSeedPhrase(seed.seedPhrase), "Seed Phrase must be valid");
      strict(derivedKeys.length >= 1, "Atleast one account must be generated");
    });

    it(`#should be able to change seedphrase, manualSync=${mode}`, async function () {
      const oldSeedPhrase = "verb there excuse wink merge phrase alien senior surround fluid remind chef bar move become";
      await tb._initializeNewKey({ initializeModules: true });
      await tb.modules.seedPhrase.setSeedPhrase("HD Key Tree", oldSeedPhrase);
      // await tb.modules.seedPhrase.setSeedPhrase("HD Key Tree");
      await tb.syncLocalMetadataTransitions();

      const newSeedPhrase = "trim later month olive fit shoulder entry laptop jeans affair belt drip jealous mirror fancy";
      await tb.modules.seedPhrase.CRITICAL_changeSeedPhrase(oldSeedPhrase, newSeedPhrase);
      await tb.syncLocalMetadataTransitions();

      const secondStoredSeedPhrases = await tb.modules.seedPhrase.getSeedPhrases();

      strictEqual(secondStoredSeedPhrases[0].seedPhrase, newSeedPhrase);
    });

    it(`#should be able to replace numberOfWallets seed phrase module, manualSync=${mode}`, async function () {
      await tb._initializeNewKey({ initializeModules: true });
      await tb.modules.seedPhrase.setSeedPhrase("HD Key Tree");
      await tb.modules.seedPhrase.setSeedPhrase("HD Key Tree");
      const seedPhraseStores = await tb.modules.seedPhrase.getSeedPhrases();
      await tb.modules.seedPhrase.setSeedPhraseStoreItem({
        id: seedPhraseStores[1].id,
        seedPhrase: seedPhraseStores[1].seedPhrase,
        numberOfWallets: 2,
      });
      await tb.syncLocalMetadataTransitions();

      const secondStoredSeedPhrases = await tb.modules.seedPhrase.getSeedPhrases();
      strictEqual(secondStoredSeedPhrases[0].numberOfWallets, 1);
      strictEqual(secondStoredSeedPhrases[1].numberOfWallets, 2);
    });

    it(`#should be able to get/set private key, manualSync=${mode}`, async function () {
      await tb._initializeNewKey({ initializeModules: true });

      const actualPrivateKeys = [
        BigInt("0x4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390"),
        BigInt("0x1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0"),
        BigInt(
          "0x7a3118ccdd405b2750271f51cc8fe237d9863584173aec3fa4579d40e5b4951215351c3d54ef416e49567b79c42fd985fcda60a6da9a794e4e844ac8dec47e98"
        ),
      ];
      await tb.modules.privateKeyModule.setPrivateKey("secp256k1n", actualPrivateKeys[0]);
      await tb.modules.privateKeyModule.setPrivateKey("secp256k1n", actualPrivateKeys[1]);
      await tb.modules.privateKeyModule.setPrivateKey("ed25519", actualPrivateKeys[2]);
      await tb.syncLocalMetadataTransitions();
      await tb.modules.privateKeyModule.getAccounts();

      const getAccounts = await tb.modules.privateKeyModule.getAccounts();
      deepStrictEqual(
        actualPrivateKeys.map((x) => x.toString(16)),
        getAccounts.map((x) => x.toString(16))
      );
    });

    it(`#should be able to get/set private key, manualSync=${mode}`, async function () {
      await tb._initializeNewKey({ initializeModules: true });

      const actualPrivateKeys = [
        BigInt("0x4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390"),
        BigInt("0x1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0"),
        BigInt(
          "0x99da9559e15e913ee9ab2e53e3dfad575da33b49be1125bb922e33494f4988281b2f49096e3e5dbd0fcfa9c0c0cd92d9ab3b21544b34d5dd4a65d98b878b9922"
        ),
      ];

      await tb.modules.privateKeyModule.setPrivateKey("secp256k1n", actualPrivateKeys[0]);
      await tb.modules.privateKeyModule.setPrivateKey("secp256k1n", actualPrivateKeys[1]);
      await tb.modules.privateKeyModule.setPrivateKey("ed25519", actualPrivateKeys[2]);
      await tb.syncLocalMetadataTransitions();
      await tb.modules.privateKeyModule.getAccounts();

      const getAccounts = await tb.modules.privateKeyModule.getAccounts();
      deepStrictEqual(
        actualPrivateKeys.map((x) => x.toString(16)),
        getAccounts.map((x) => x.toString(16))
      );
    });

    it(`#should be able to generate private key if not given, manualSync=${mode}`, async function () {
      await tb._initializeNewKey({ initializeModules: true });

      await tb.modules.privateKeyModule.setPrivateKey("secp256k1n");
      await tb.modules.privateKeyModule.setPrivateKey("secp256k1n");
      await tb.modules.privateKeyModule.setPrivateKey("ed25519");
      await tb.syncLocalMetadataTransitions();

      const accounts = await tb.modules.privateKeyModule.getAccounts();
      strictEqual(accounts.length, 3);
    });

    it(`#should be able to get/set private keys and seed phrase, manualSync=${mode}`, async function () {
      const resp1 = await tb._initializeNewKey({ initializeModules: true });

      await tb.modules.seedPhrase.setSeedPhrase("HD Key Tree", "seed sock milk update focus rotate barely fade car face mechanic mercy");
      await tb.modules.seedPhrase.setSeedPhrase("HD Key Tree", "chapter gas cost saddle annual mouse chef unknown edit pen stairs claw");

      const actualPrivateKeys = [
        BigInt("0x4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390"),
        BigInt("0x1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0"),
      ];
      await tb.modules.privateKeyModule.setPrivateKey("secp256k1n", actualPrivateKeys[0]);
      await tb.modules.privateKeyModule.setPrivateKey("secp256k1n", actualPrivateKeys[1]);
      await tb.syncLocalMetadataTransitions();

      const metamaskSeedPhraseFormat2 = new MetamaskSeedPhraseFormat(
        new JsonRpcProvider("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68")
      );
      const tb2 = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: mode,
        storageLayer: customSL,
        modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat2]), privateKeyModule: new PrivateKeyModule([secp256k1Format]) },
      });
      await tb2.initialize();
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();

      compareReconstructedKeys(reconstructedKey, {
        secp256k1Key: resp1.secp256k1Key,
        seedPhraseModule: [
          BigInt("0x70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46"),
          BigInt("0x4d62a55af3496a7b290a12dd5fd5ef3e051d787dbc005fb74536136949602f9e"),
        ],
        privateKeyModule: [
          BigInt("0x4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390"),
          BigInt("0x1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0"),
        ],
        allKeys: [
          resp1.secp256k1Key,
          BigInt("0x70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46"),
          BigInt("0x4d62a55af3496a7b290a12dd5fd5ef3e051d787dbc005fb74536136949602f9e"),
          BigInt("0x4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390"),
          BigInt("0x1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0"),
        ],
      });

      const reconstructedKey2 = await tb2.reconstructKey(false);
      compareReconstructedKeys(reconstructedKey2, {
        secp256k1Key: resp1.secp256k1Key,
        allKeys: [resp1.secp256k1Key],
      });
    });

    it(`#should be able to increase threshold limit of tkey, manualSync=${mode}`, async function () {
      // tkey instance with correct share stores and index
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      const resp2 = await tb2._initializeNewKey({ initializeModules: true });
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
      await tb3._refreshShares(newThreshold, existingShareIndexes, poly.getPolynomialID());

      // 3/4 shares is required to reconstruct tkey
      const reconstructPostThreshold = await tb3.reconstructKey();
      if (reconstructPreThreshold.secp256k1Key !== reconstructPostThreshold.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
      // console.log("newThreshold", tb3.metadata.getLatestPublicPolynomial().getThreshold());
      equal(tb3.metadata.getLatestPublicPolynomial().getThreshold(), newThreshold);
    });
  });

  describe("Tkey LocalMetadataTransition", function () {
    it("should able to get latest share from getGenericMetadataWithTransitionStates with localMetadataTransision", async function () {
      const tb = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: true,
        storageLayer: customSL,
      });

      await tb._initializeNewKey();

      await tb.reconstructKey();

      await tb.generateNewShare();

      const expectLatestSPShare = await tb.getGenericMetadataWithTransitionStates({
        fromJSONConstructor: ShareStore,
        serviceProvider: customSP,
        includeLocalMetadataTransitions: true,
        _localMetadataTransitions: tb._localMetadataTransitions,
      });

      const latestSPShareStore = tb.outputShareStore(1n);

      strictEqual(JSON.stringify(latestSPShareStore.toJSON()), JSON.stringify(expectLatestSPShare.toJSON()));
    });

    it("should able to get catchupToLatestShare with localMetadataTransision", async function () {
      const tb = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: true,
        storageLayer: customSL,
      });

      await tb._initializeNewKey();
      const spShareStore = tb.outputShareStore(1n);

      await tb.reconstructKey();

      await tb.generateNewShare();

      const expectLatestResult = await tb.catchupToLatestShare({
        shareStore: spShareStore,
        includeLocalMetadataTransitions: true,
      });

      const latestSPShareStore = tb.outputShareStore(1n);

      strictEqual(JSON.stringify(latestSPShareStore.toJSON()), JSON.stringify(expectLatestResult.latestShare.toJSON()));
      strictEqual(JSON.stringify(tb.metadata.toJSON()), JSON.stringify(expectLatestResult.shareMetadata.toJSON()));
    });

    it("should able to initialize and reconstruct with localMetadataTransision", async function () {
      const tb = new ThresholdKey({
        serviceProvider: customSP,
        manualSync: true,
        storageLayer: customSL,
      });

      await tb._initializeNewKey();

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

      strictEqual(tb.secp256k1Key.toString(16), tb2.secp256k1Key.toString(16));
    });
  });

  describe("Lock", function () {
    it(`#locks should fail when tkey/nonce is updated, manualSync=${mode}`, async function () {
      const tb = new ThresholdKey({ serviceProvider: customSP, manualSync: mode, storageLayer: customSL });
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, manualSync: mode, storageLayer: customSL });
      await tb2.initialize();
      tb2.inputShareStore(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
      await tb2.generateNewShare();
      await tb2.syncLocalMetadataTransitions();

      await rejects(
        async () => {
          await tb.generateNewShare();
          await tb.syncLocalMetadataTransitions();
        },
        (err) => {
          strictEqual(err.code, 1401, "Expected aquireLock failed error is not thrown");
          return true;
        }
      );
    });

    it(`#locks should not allow for writes of the same nonce, manualSync=${mode}`, async function () {
      const tb = new ThresholdKey({ serviceProvider: customSP, manualSync: mode, storageLayer: customSL });
      const resp1 = await tb._initializeNewKey({ initializeModules: true });
      await tb.syncLocalMetadataTransitions();

      const tb2 = new ThresholdKey({ serviceProvider: customSP, manualSync: mode, storageLayer: customSL });
      await tb2.initialize();
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.secp256k1Key !== reconstructedKey.secp256k1Key) {
        fail("key should be able to be reconstructed");
      }
      const alltbs = [];
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
      if (count !== 1) {
        fail("fulfilled count != 1");
      }
    });
  });

  describe("tkey error cases", function () {
    let tb;
    let resp1;
    let sandbox;

    before("Setup ThresholdKey", async function () {
      sandbox = createSandbox();
      tb = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      resp1 = await tb._initializeNewKey({ initializeModules: true });
      await tb.syncLocalMetadataTransitions();
    });

    afterEach(function () {
      sandbox.restore();
    });

    it(`#should throw error code 1101 if metadata is undefined, in manualSync: ${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await rejects(
        async () => {
          await tb2.reconstructKey();
        },
        (err) => {
          strictEqual(err.code, 1101, "Expected metadata error is not thrown");
          return true;
        }
      );
      await rejects(
        async () => {
          tb2.getMetadata();
        },
        (err) => {
          strictEqual(err.code, 1101, "Expected metadata error is not thrown");
          return true;
        }
      );
      await rejects(
        async () => {
          await tb2.deleteShare();
        },
        (err) => {
          strictEqual(err.code, 1101, "Expected metadata error is not thrown");
          return true;
        }
      );
      await rejects(
        async () => {
          await tb2.generateNewShare();
        },
        (err) => {
          strictEqual(err.code, 1101, "Expected metadata error is not thrown");
          return true;
        }
      );
      const exportedSeedShare = await tb.outputShare(resp1.deviceShare.share.shareIndex, "mnemonic");
      await rejects(
        async () => {
          await tb2.inputShare(exportedSeedShare, "mnemonic");
        },
        (err) => {
          strictEqual(err.code, 1101, "Expected metadata error is not thrown");
          return true;
        }
      );
    });

    it(`#should throw error code 1301 if privKey is not available, in manualSync: ${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ neverInitializeNewKey: true });
      await rejects(
        async () => {
          await tb2.generateNewShare();
        },
        (err) => {
          strictEqual(err.code, 1301, "Expected 1301 error is not thrown");
          return true;
        }
      );
      await rejects(
        async () => {
          await tb2.deleteShare();
        },
        (err) => {
          strictEqual(err.code, 1301, "Expected 1301 error is not thrown");
          return true;
        }
      );
      await rejects(
        async () => {
          await tb2.encrypt(utf8ToBytes("test data"));
        },
        (err) => {
          strictEqual(err.code, 1301, "Expected 1301 error is not thrown");
          return true;
        }
      );
    });

    it(`#should throw error code 1302 if not enough shares are avaible for reconstruction, in manualSync: ${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ neverInitializeNewKey: true });
      await rejects(
        async () => {
          await tb2.reconstructKey();
        },
        (err) => {
          strictEqual(err.code, 1302, "Expected 1302 error is not thrown");
          return true;
        }
      );
    });

    it(`#should throw error code 1102 if metadata get failed, in manualSync: ${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      sandbox.stub(tb2.storageLayer, "getMetadata").throws(new Error("failed to fetch metadata"));
      await rejects(
        async () => {
          await tb2.initialize({ neverInitializeNewKey: true });
        },
        (err) => {
          strictEqual(err.code, 1102, "Expected 1102 error is not thrown");
          return true;
        }
      );
    });

    it(`#should throw error code 1103 if metadata post failed, in manualSync: ${mode}`, async function () {
      const tb2 = new ThresholdKey({ serviceProvider: customSP, storageLayer: customSL, manualSync: mode });
      await tb2.initialize({ neverInitializeNewKey: true });
      await tb2.inputShareStoreSafe(resp1.deviceShare);
      await tb2.reconstructKey();
      await tb2.syncLocalMetadataTransitions();
      sandbox.stub(tb2.storageLayer, "setMetadataStream").throws(new Error("failed to set metadata"));
      if (mode) {
        await rejects(
          async () => {
            await tb2.addShareDescription(resp1.deviceShare.share.shareIndex.toString(16), JSON.stringify({ test: "unit test" }), true);
            await tb2.syncLocalMetadataTransitions();
          },
          (err) => {
            strictEqual(err.code, 1103, "Expected 1103 error is not thrown");
            return true;
          }
        );
      } else {
        await rejects(
          async () => {
            await tb2.addShareDescription(resp1.deviceShare.share.shareIndex.toString(16), JSON.stringify({ test: "unit test" }), true);
          },
          (err) => {
            strictEqual(err.code, 1103, "Expected 1103 error is not thrown");
            return true;
          }
        );
      }
    });
  });

  describe("OneKey", function () {
    if (!mode || isMocked) return;

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
      const { nonce, pubNonce, upgraded: isUpgraded } = nonceRes;
      notEqual(nonce, undefined);
      notEqual(pubNonce, undefined);
      equal(isUpgraded, false);

      const nonceBN = BigInt(`0x${nonce}`);
      const importKey = ((postboxKeyBN + nonceBN) % secp256k1.CURVE.n).toString(16);

      const tKey = new ThresholdKey({ serviceProvider, storageLayer: storageLayer2, manualSync: mode });
      await tKey.initialize({
        importKey: BigInt(`0x${importKey}`),
        delete1OutOf1: true,
      });
      await tKey.syncLocalMetadataTransitions();
      equal(tKey.secp256k1Key.toString(16), importKey);

      const {
        nonce: newNonce,
        pubNonce: newPubNonce,
        upgraded,
      } = await getOrSetNonce(
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
      equal(upgraded, true);
      equal(newNonce, undefined);
      deepEqual(pubNonce, newPubNonce);
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
      equal(res.typeOfUser, "v1");

      const anotherRes = await getOrSetNonce(
        metadataUrl,
        serviceProvider.customAuthInstance.torus.ec,
        0,
        pubKeyPoint.x.toString(16),
        pubKeyPoint.y.toString(16),
        postboxKeyBN
      );
      deepEqual(res, anotherRes);
    });

    // it("should not change v1 address with a custom nonce when getOrSetNonce is called", async function () {
    //   // Create an existing v1 account with custom key
    //   const postboxKeyBN = new BN(generatePrivate(), "hex");
    //   const pubKeyPoint = getPubKeyPoint(postboxKeyBN);
    //   const customKey = generatePrivate().toString(16);

    //   const serviceProvider = new TorusServiceProvider({
    //     postboxKey: postboxKeyBN.toString(16),
    //     customAuthArgs: {
    //       enableOneKey: true,
    //       metadataUrl: getMetadataUrl(),
    //       // This url has no effect as postbox key is passed, passing it just to satisfy direct auth checks.
    //       baseUrl: "http://localhost:3000",
    //       web3AuthClientId: "test",
    //       network: "mainnet",
    //     },
    //   });
    //   // TODO: this is deprecated
    //   await serviceProvider.customAuthInstance.torus.setCustomKey({ torusKeyHex: postboxKeyBN.toString(16), customKeyHex: customKey.toString(16) });

    //   // Compare nonce returned from v1 API and v2 API
    //   const getMetadataNonce = await serviceProvider.customAuthInstance.torus.getMetadata({
    //     pub_key_X: pubKeyPoint.x.toString(16),
    //     pub_key_Y: pubKeyPoint.y.toString(16),
    //   });
    //   const getOrSetNonce = await serviceProvider.customAuthInstance.torus.getOrSetNonce(
    //     pubKeyPoint.x.toString(16),
    //     pubKeyPoint.y.toString(16),
    //     postboxKeyBN
    //   );
    //   equal(getOrSetNonce.typeOfUser, "v1");
    //   equal(getOrSetNonce.nonce, getMetadataNonce.toString(16));
    // });
  });

  ed25519Tests({ manualSync: mode, torusSP: customSP, storageLayer: customSL });
};
