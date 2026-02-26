import { EllipticPoint, KeyType, Point } from "@tkey/common-types";
import assert, { deepStrictEqual, equal, fail, rejects } from "assert";
import BN from "bn.js";
import { ec as EC } from "elliptic";

import { TKeyTSS as ThresholdKey, TKeyTSS, TSSTorusServiceProvider } from "../src";
import { factorKeyCurve } from "../src/tss";
import { getLagrangeCoeffs } from "../src/util";
import { assignTssDkgKeys, fetchPostboxKeyAndSigs, generateKey, initStorageLayer } from "./helpers";

const TEST_KEY_TYPES = [KeyType.secp256k1, KeyType.ed25519];

TEST_KEY_TYPES.forEach((TSS_KEY_TYPE) => {
  const ecFactor = factorKeyCurve;
  const ecTSS = new EC(TSS_KEY_TYPE);

  const torusSP = new TSSTorusServiceProvider({
    customAuthArgs: {
      network: "sapphire_devnet",
      web3AuthClientId: "YOUR_CLIENT_ID",
      baseUrl: "http://localhost:3000",
      keyType: TSS_KEY_TYPE,
    },
  });

  const torusSL = initStorageLayer();

  const manualSync = true;

  describe(`TSS tests, keyType=${TSS_KEY_TYPE}`, function () {
    it("#should be able to reconstruct tss share from factor key", async function () {
      const sp = torusSP;

      const deviceTSSShare = ecTSS.genKeyPair().getPrivate();
      const deviceTSSIndex = 3;

      sp.authConnectionId = "torus-test-health";
      sp.userId = "test@example.com";
      const { postboxkey } = await fetchPostboxKeyAndSigs({
        serviceProvider: sp,
        authConnectionId: sp.authConnectionId,
        userId: sp.userId,
      });
      sp.postboxKey = postboxkey;

      const storageLayer2 = initStorageLayer();
      const tb1 = new ThresholdKey({
        serviceProvider: sp,
        storageLayer: storageLayer2,
        manualSync,
        tssKeyType: TSS_KEY_TYPE,
      });

      // factor key needs to passed from outside of tKey
      const factorKeyPair = ecFactor.genKeyPair();
      const factorKey = factorKeyPair.getPrivate();
      const factorPub = Point.fromElliptic(factorKeyPair.getPublic());

      await tb1.initialize({ factorPub, deviceTSSShare, deviceTSSIndex });
      const reconstructedKey = await tb1.reconstructKey();
      await tb1.syncLocalMetadataTransitions();
      if (tb1.secp256k1Key.cmp(reconstructedKey.secp256k1Key) !== 0) {
        fail("key should be able to be reconstructed");
      }
      const { tssShare: tss2 } = await tb1.getTSSShare(factorKey);

      const tssCommits = tb1.getTSSCommits();
      const tss2Pub = ecTSS.g.mul(tss2);
      const tssCommitA0 = tssCommits[0].toEllipticPoint(ecTSS);
      const tssCommitA1 = tssCommits[1].toEllipticPoint(ecTSS);
      const _tss2Pub = tssCommitA0.add(tssCommitA1.mul(new BN(deviceTSSIndex)));
      equal(tss2Pub.eq(_tss2Pub), true);
    });

    it("#should be able to reconstruct tss key from factor key", async function () {
      const sp = torusSP;

      sp.authConnectionId = "torus-test-health";
      sp.userId = "test18@example.com";
      const { serverDKGPrivKeys } = await assignTssDkgKeys({
        serviceProvider: sp,
        authConnectionId: sp.authConnectionId,
        userId: sp.userId,
        maxTSSNonceToSimulate: 2,
      });

      const tss1 = new BN(serverDKGPrivKeys[0], "hex");
      const deviceTSSShare = ecTSS.genKeyPair().getPrivate();
      const deviceTSSIndex = 2;
      const { postboxkey } = await fetchPostboxKeyAndSigs({
        serviceProvider: sp,
        authConnectionId: sp.authConnectionId,
        userId: sp.userId,
      });
      sp.postboxKey = postboxkey;
      const storageLayer = initStorageLayer();
      const tb1 = new ThresholdKey({ serviceProvider: sp, storageLayer, manualSync, tssKeyType: TSS_KEY_TYPE });

      // factor key needs to passed from outside of tKey
      const factorKeyPair = ecFactor.genKeyPair();
      const factorKey = factorKeyPair.getPrivate();
      const factorPub = Point.fromElliptic(factorKeyPair.getPublic());

      await tb1.initialize({ factorPub, deviceTSSShare, deviceTSSIndex });
      const reconstructedKey = await tb1.reconstructKey();
      await tb1.syncLocalMetadataTransitions();
      if (tb1.secp256k1Key.cmp(reconstructedKey.secp256k1Key) !== 0) {
        fail("key should be able to be reconstructed");
      }

      const { tssShare: tss2 } = await tb1.getTSSShare(factorKey);
      const tssCommits = tb1.getTSSCommits();

      const tssPrivKey = getLagrangeCoeffs(ecTSS, [1, deviceTSSIndex], 1)
        .mul(tss1)
        .add(getLagrangeCoeffs(ecTSS, [1, deviceTSSIndex], deviceTSSIndex).mul(tss2))
        .umod(ecTSS.n);

      const tssPubKey = (ecTSS.g as EllipticPoint).mul(tssPrivKey);
      const tssCommits0 = tssCommits[0].toEllipticPoint(ecTSS);
      const tssPub = tb1.getTSSPub().toEllipticPoint(ecTSS);
      equal(tssPubKey.eq(tssCommits0), true);
      equal(tssPub.eq(tssPubKey), true);

      // With account index.
      if (tb1.tssKeyType !== KeyType.ed25519) {
        const accountIndex = Math.floor(Math.random() * 99) + 1;
        const tss1Account = (() => {
          const share = new BN(serverDKGPrivKeys[0], "hex");
          const nonce = tb1.computeAccountNonce(accountIndex);
          return share.add(nonce).umod(ecTSS.n);
        })();
        const { tssShare: tss2Account } = await tb1.getTSSShare(factorKey, { accountIndex });

        const coefficient1 = getLagrangeCoeffs(ecTSS, [1, deviceTSSIndex], 1);
        const coefficient2 = getLagrangeCoeffs(ecTSS, [1, deviceTSSIndex], deviceTSSIndex);
        const tssKey = coefficient1.mul(tss1Account).add(coefficient2.mul(tss2Account)).umod(ecTSS.n);

        const tssKeyPub = (ecTSS.g as EllipticPoint).mul(tssKey);
        const tssPubAccount = tb1.getTSSPub(accountIndex).toEllipticPoint(ecTSS);
        equal(tssPubAccount.eq(tssKeyPub), true, "should equal account pub key");
      }
    });

    it(`#should be able to import a tss key for new account, manualSync=${manualSync}`, async function () {
      const sp = torusSP;
      sp.authConnectionId = "torus-test-health";
      sp.userId = `importeduserfresh${TSS_KEY_TYPE}@example.com`;
      const { signatures, postboxkey } = await fetchPostboxKeyAndSigs({
        serviceProvider: sp,
        authConnectionId: sp.authConnectionId,
        userId: sp.userId,
      });
      sp.postboxKey = postboxkey;

      const tb = new ThresholdKey({ serviceProvider: sp, storageLayer: torusSL, manualSync, tssKeyType: TSS_KEY_TYPE });

      const factorKeyPair = ecFactor.genKeyPair();
      const factorKey = factorKeyPair.getPrivate();
      const factorPub = Point.fromElliptic(factorKeyPair.getPublic());

      const importTssKey = generateKey(TSS_KEY_TYPE);
      const newTSSIndex = 2;

      await tb.initialize({ skipTssInit: true });
      await tb.reconstructKey();
      await tb.importTssKey(
        { tag: "imported", importKey: importTssKey.raw, factorPub, newTSSIndex },
        {
          authSignatures: signatures,
        }
      );

      await tb.syncLocalMetadataTransitions();

      // Check pub key.
      const importTssKeyPub = Point.fromScalar(importTssKey.scalar, tb.tssCurve);
      const tssPub = await tb.getTSSPub();
      assert(tssPub.equals(importTssKeyPub));

      // Check exported key.
      const exportedKey = await tb._UNSAFE_exportTssKey({
        factorKey,
        authSignatures: signatures,
      });
      assert(exportedKey.eq(importTssKey.scalar));
      if (TSS_KEY_TYPE === KeyType.ed25519) {
        const seed = await tb._UNSAFE_exportTssEd25519Seed({
          factorKey,
          authSignatures: signatures,
        });
        deepStrictEqual(new Uint8Array(seed), new Uint8Array(importTssKey.raw));
      } else {
        // If not ed25519, then also check exporting with account index.
        const exportedKeyIndex2 = await tb._UNSAFE_exportTssKey({
          factorKey,
          authSignatures: signatures,
          accountIndex: 2,
        });
        const exportedPubKeyIndex2 = Point.fromScalar(exportedKeyIndex2, tb.tssCurve);
        const pubKeyIndex2 = tb.getTSSPub(2);
        assert(exportedPubKeyIndex2.equals(pubKeyIndex2));
      }
    });

    it(`#should be able to import a tss key for existing account, manualSync=${manualSync}`, async function () {
      const sp = torusSP;

      const deviceTSSShare = ecTSS.genKeyPair().getPrivate();
      const deviceTSSIndex = 2;
      const newTSSIndex = 3;

      sp.authConnectionId = "torus-test-health";
      sp.userId = `importeduser${TSS_KEY_TYPE}@example.com`;
      const { signatures, postboxkey } = await fetchPostboxKeyAndSigs({
        serviceProvider: sp,
        authConnectionId: sp.authConnectionId,
        userId: sp.userId,
      });
      sp.postboxKey = postboxkey;
      const { serverDKGPrivKeys } = await assignTssDkgKeys({
        serviceProvider: sp,
        authConnectionId: sp.authConnectionId,
        userId: sp.userId,
        maxTSSNonceToSimulate: 1,
      });

      const tb = new ThresholdKey({ serviceProvider: sp, storageLayer: torusSL, manualSync, tssKeyType: TSS_KEY_TYPE });

      // factor key needs to passed from outside of tKey
      const factorKeyPair = ecFactor.genKeyPair();
      const factorKey = factorKeyPair.getPrivate();
      const factorPub = Point.fromElliptic(factorKeyPair.getPublic());
      // 2/2
      await tb.initialize({ factorPub, deviceTSSShare, deviceTSSIndex });
      const newShare = await tb.generateNewShare();

      const reconstructedKey = await tb.reconstructKey();
      await tb.syncLocalMetadataTransitions();

      if (tb.secp256k1Key.cmp(reconstructedKey.secp256k1Key) !== 0) {
        fail("key should be able to be reconstructed");
      }
      const { tssShare: retrievedTSS, tssIndex: retrievedTSSIndex } = await tb.getTSSShare(factorKey);
      const tssCommits = tb.getTSSCommits();
      const tssPrivKey = getLagrangeCoeffs(ecTSS, [1, retrievedTSSIndex], 1)
        .mul(serverDKGPrivKeys[0])
        .add(getLagrangeCoeffs(ecTSS, [1, retrievedTSSIndex], retrievedTSSIndex).mul(retrievedTSS))
        .umod(ecTSS.n);
      const tssPubKey = (ecTSS.g as EllipticPoint).mul(tssPrivKey);

      const tssCommits0 = tssCommits[0].toEllipticPoint(ecTSS);
      equal(tssPubKey.eq(tssCommits0), true);

      const { serverDKGPrivKeys: serverDKGPrivKeys1 } = await assignTssDkgKeys({
        tssTag: "imported",
        serviceProvider: sp,
        authConnectionId: sp.authConnectionId,
        userId: sp.userId,
        maxTSSNonceToSimulate: 1,
      });

      // import key
      const { raw: importedKey, scalar: importedScalar } = generateKey(TSS_KEY_TYPE);
      await tb.importTssKey(
        { tag: "imported", importKey: importedKey, factorPub, newTSSIndex },
        {
          authSignatures: signatures,
        }
      );
      // tag is switched to imported
      await tb.syncLocalMetadataTransitions();
      // for imported key
      const { tssShare: retrievedTSS1, tssIndex: retrievedTSSIndex1 } = await tb.getTSSShare(factorKey);

      const tssCommits1 = tb.getTSSCommits();
      const tssPrivKey1 = getLagrangeCoeffs(ecTSS, [1, retrievedTSSIndex1], 1)
        .mul(serverDKGPrivKeys1[0])
        .add(getLagrangeCoeffs(ecTSS, [1, retrievedTSSIndex1], retrievedTSSIndex1).mul(retrievedTSS1))
        .umod(ecTSS.n);
      const tssPubKey1 = (ecTSS.g as EllipticPoint).mul(tssPrivKey1);

      const tssCommits10 = tssCommits1[0].toEllipticPoint(ecTSS);
      equal(tssPubKey1.eq(tssCommits10), true);
      equal(tssPrivKey1.toString("hex"), importedScalar.toString("hex"));

      if (TSS_KEY_TYPE === KeyType.ed25519) {
        const seed = await tb._UNSAFE_exportTssEd25519Seed({
          factorKey,
          selectedServers: [1, 2, 3],
          authSignatures: signatures,
        });
        deepStrictEqual(new Uint8Array(seed), new Uint8Array(importedKey));
      }

      const tb2 = new ThresholdKey({ serviceProvider: sp, storageLayer: torusSL, manualSync, tssKeyType: TSS_KEY_TYPE });

      await tb2.initialize({ factorPub });
      tb2.inputShareStore(newShare.newShareStores[newShare.newShareIndex.toString("hex")]);
      const reconstructedKey2 = await tb2.reconstructKey();
      await tb2.syncLocalMetadataTransitions();

      if (tb2.secp256k1Key.cmp(reconstructedKey2.secp256k1Key) !== 0) {
        fail("key should be able to be reconstructed");
      }
      const tssCommits2 = tb2.getTSSCommits();
      const tssCommits20 = tssCommits2[0].toEllipticPoint(ecTSS);
      equal(tssPubKey.eq(tssCommits20), true);

      // switch to imported account
      tb2.tssTag = "imported";
      const { tssShare: retrievedTSSImported, tssIndex: retrievedTSSIndexImported } = await tb2.getTSSShare(factorKey);

      const tssCommitsImported = tb2.getTSSCommits();

      const tssPrivKeyImported = getLagrangeCoeffs(ecTSS, [1, retrievedTSSIndexImported], 1)
        .mul(serverDKGPrivKeys1[0])
        .add(getLagrangeCoeffs(ecTSS, [1, retrievedTSSIndexImported], retrievedTSSIndexImported).mul(retrievedTSSImported))
        .umod(ecTSS.n);

      const tssPubKeyImported = (ecTSS.g as EllipticPoint).mul(tssPrivKeyImported);

      const tssCommitsImported0 = tssCommitsImported[0].toEllipticPoint(ecTSS);
      equal(tssPubKeyImported.eq(tssCommitsImported0), true);
      equal(tssPrivKeyImported.toString("hex"), importedScalar.toString("hex"));
    });

    it(`#should be able to unsafe export final tss key, manualSync=${manualSync}`, async function () {
      const sp = torusSP;

      const deviceTSSShare = ecTSS.genKeyPair().getPrivate();
      const deviceTSSIndex = 3;

      sp.authConnectionId = "torus-test-health";
      sp.userId = `exportUser${TSS_KEY_TYPE}@example.com-1`;
      const { signatures, postboxkey } = await fetchPostboxKeyAndSigs({
        serviceProvider: sp,
        authConnectionId: sp.authConnectionId,
        userId: sp.userId,
      });
      sp.postboxKey = postboxkey;
      const { serverDKGPrivKeys } = await assignTssDkgKeys({
        serviceProvider: sp,
        authConnectionId: sp.authConnectionId,
        userId: sp.userId,
        maxTSSNonceToSimulate: 1,
      });

      const tb = new ThresholdKey({ serviceProvider: sp, storageLayer: torusSL, manualSync, tssKeyType: TSS_KEY_TYPE });

      // factor key needs to passed from outside of tKey
      const factorKeyPair = ecFactor.genKeyPair();
      const factorKey = factorKeyPair.getPrivate();
      const factorPub = Point.fromElliptic(factorKeyPair.getPublic());

      // 2/2
      await tb.initialize({ factorPub, deviceTSSShare, deviceTSSIndex });
      const newShare = await tb.generateNewShare();

      const reconstructedKey = await tb.reconstructKey();
      await tb.syncLocalMetadataTransitions();

      if (tb.secp256k1Key.cmp(reconstructedKey.secp256k1Key) !== 0) {
        fail("key should be able to be reconstructed");
      }
      const { tssShare: retrievedTSS, tssIndex: retrievedTSSIndex } = await tb.getTSSShare(factorKey);
      const tssCommits = tb.getTSSCommits();
      const tssPrivKey = getLagrangeCoeffs(ecTSS, [1, retrievedTSSIndex], 1)
        .mul(serverDKGPrivKeys[0])
        .add(getLagrangeCoeffs(ecTSS, [1, retrievedTSSIndex], retrievedTSSIndex).mul(retrievedTSS))
        .umod(ecTSS.n);
      const tssPubKey = (ecTSS.g as EllipticPoint).mul(tssPrivKey);

      const tssCommits0 = tssCommits[0].toEllipticPoint(ecTSS);
      equal(tssPubKey.eq(tssCommits0), true);

      await assignTssDkgKeys({
        tssTag: "imported",
        serviceProvider: sp,
        authConnectionId: sp.authConnectionId,
        userId: sp.userId,
        maxTSSNonceToSimulate: 1,
      });
      // import key
      const { raw: importedKey, scalar: importedScalar } = generateKey(TSS_KEY_TYPE);
      const importedIndex = 2;
      await tb.importTssKey(
        { tag: "imported", importKey: importedKey, factorPub, newTSSIndex: importedIndex },
        {
          authSignatures: signatures,
        }
      );
      // tag is switched to imported
      await tb.syncLocalMetadataTransitions();
      // for imported key
      {
        const finalPubKey = tb.getTSSCommits()[0].toEllipticPoint(ecTSS);

        const finalTssKey = await tb._UNSAFE_exportTssKey({
          factorKey,
          selectedServers: [1, 2, 3],
          authSignatures: signatures,
        });
        const tssPubKeyImported = (ecTSS.g as EllipticPoint).mul(importedScalar);

        equal(finalTssKey.toString("hex"), importedScalar.toString("hex"));
        equal(tssPubKeyImported.eq(finalPubKey), true);

        if (TSS_KEY_TYPE === KeyType.ed25519) {
          const seed = await tb._UNSAFE_exportTssEd25519Seed({
            factorKey,
            selectedServers: [3, 4, 5],
            authSignatures: signatures,
          });
          deepStrictEqual(new Uint8Array(seed), new Uint8Array(importedKey));
        }
      }
      {
        tb.tssTag = "default";

        const finalPubKey = tb.getTSSCommits()[0].toEllipticPoint(ecTSS);

        const finalTssKey = await tb._UNSAFE_exportTssKey({
          factorKey,
          selectedServers: [1, 2, 3],
          authSignatures: signatures,
        });
        const tssPubKeyImported = (ecTSS.g as EllipticPoint).mul(finalTssKey);

        equal(tssPubKeyImported.eq(finalPubKey), true);
      }

      const tb2 = new ThresholdKey({ serviceProvider: sp, storageLayer: torusSL, manualSync, tssKeyType: TSS_KEY_TYPE });

      await tb2.initialize({ factorPub });
      tb2.inputShareStore(newShare.newShareStores[newShare.newShareIndex.toString("hex")]);
      await tb2.reconstructKey();
      await tb2.syncLocalMetadataTransitions();
      {
        tb2.tssTag = "imported";
        const finalPubKey = tb2.getTSSCommits()[0].toEllipticPoint(ecTSS);

        const finalTssKey = await tb2._UNSAFE_exportTssKey({
          factorKey,
          selectedServers: [1, 2, 3],
          authSignatures: signatures,
        });
        const tssPubKeyImported = (ecTSS.g as EllipticPoint).mul(finalTssKey);

        equal(finalTssKey.toString("hex"), importedScalar.toString("hex"));
        equal(tssPubKeyImported.eq(finalPubKey), true);
      }
      {
        tb2.tssTag = "default";

        const finalPubKey = tb2.getTSSCommits()[0].toEllipticPoint(ecTSS);

        const finalTssKey = await tb2._UNSAFE_exportTssKey({
          factorKey,
          selectedServers: [1, 2, 3],
          authSignatures: signatures,
        });
        const tssPubKeyImported = (ecTSS.g as EllipticPoint).mul(finalTssKey);

        equal(tssPubKeyImported.eq(finalPubKey), true);
      }
    });

    describe(`factor addition and removal, manualSync=${manualSync}`, function () {
      let tb: TKeyTSS;
      let factorKey: BN;
      let newFactorKeySameIndex: BN;
      let newFactorKeyNewIndex: BN;
      let signatures: string[];

      const deviceTSSIndex = 2;
      const newTSSIndex = 3;

      before("setup", async function () {
        const sp = torusSP;
        sp.authConnectionId = "torus-test-health";
        sp.userId = `test192${TSS_KEY_TYPE}@example.com-1`;
        const { signatures: authSignatures, postboxkey } = await fetchPostboxKeyAndSigs({
          serviceProvider: sp,
          authConnectionId: sp.authConnectionId,
          userId: sp.userId,
        });
        signatures = authSignatures;
        sp.postboxKey = postboxkey;
        await assignTssDkgKeys({
          serviceProvider: sp,
          authConnectionId: sp.authConnectionId,
          userId: sp.userId,
          maxTSSNonceToSimulate: 4,
        });

        tb = new ThresholdKey({ serviceProvider: sp, storageLayer: torusSL, manualSync, tssKeyType: TSS_KEY_TYPE });

        // factor key needs to passed from outside of tKey
        const factorKeyPair = ecFactor.genKeyPair();
        factorKey = factorKeyPair.getPrivate();
        const factorPub = Point.fromElliptic(factorKeyPair.getPublic());
        const deviceTSSShare = ecTSS.genKeyPair().getPrivate();
        await tb.initialize({ factorPub, deviceTSSShare, deviceTSSIndex });
        const reconstructedKey = await tb.reconstructKey();
        await tb.syncLocalMetadataTransitions();

        if (tb.secp256k1Key.cmp(reconstructedKey.secp256k1Key) !== 0) {
          fail("key should be able to be reconstructed");
        }
      });

      it("should be able to add factor for same index", async function () {
        newFactorKeySameIndex = ecFactor.genKeyPair().getPrivate();
        const newFactorPub = (ecFactor.g as EllipticPoint).mul(newFactorKeySameIndex);
        await tb.addFactorPub({
          authSignatures: signatures,
          existingFactorKey: factorKey,
          newFactorPub: Point.fromElliptic(newFactorPub),
          newTSSIndex: deviceTSSIndex,
        });
        await tb.syncLocalMetadataTransitions();
      });

      it("should be able to add factor for different index", async function () {
        newFactorKeyNewIndex = ecFactor.genKeyPair().getPrivate();
        const newFactorPub = (ecFactor.g as EllipticPoint).mul(newFactorKeyNewIndex);
        await tb.addFactorPub({
          authSignatures: signatures,
          existingFactorKey: factorKey,
          newFactorPub: Point.fromElliptic(newFactorPub),
          newTSSIndex,
          refreshShares: true,
        });
        await tb.syncLocalMetadataTransitions();
      });

      it("should be able to remove factor for same index", async function () {
        const newFactorPub = (ecFactor.g as EllipticPoint).mul(newFactorKeySameIndex);
        await tb.deleteFactorPub({
          factorKey,
          deleteFactorPub: Point.fromElliptic(newFactorPub),
          authSignatures: signatures,
        });
        await tb.syncLocalMetadataTransitions();
      });

      it("should no longer be able to access key share with removed factor (same index)", async function () {
        await rejects(tb.getTSSShare(newFactorKeySameIndex));
      });

      it("should be able to remove factor for different index", async function () {
        const newFactorPub = (ecFactor.g as EllipticPoint).mul(newFactorKeyNewIndex);
        await tb.deleteFactorPub({
          factorKey,
          deleteFactorPub: Point.fromElliptic(newFactorPub),
          authSignatures: signatures,
        });
        await tb.syncLocalMetadataTransitions();
      });

      it("should no longer be able to access key share with removed factor (different index)", async function () {
        await rejects(tb.getTSSShare(newFactorKeyNewIndex));
      });
    });

    describe(`TSS serialization and deserialization tests, manualSync=${manualSync}`, function () {
      let tb: TKeyTSS;
      let factorKey: BN;
      let signatures: string[];

      const deviceTSSIndex = 2;
      const newTSSIndex = 3;

      const sp = torusSP;

      before("setup", async function () {
        sp.authConnectionId = "torus-test-health";
        sp.userId = `test193${TSS_KEY_TYPE}@example.com-1`;
        const { signatures: authSignatures, postboxkey } = await fetchPostboxKeyAndSigs({
          serviceProvider: sp,
          authConnectionId: sp.authConnectionId,
          userId: sp.userId,
        });
        signatures = authSignatures;

        sp.postboxKey = postboxkey;

        await assignTssDkgKeys({
          serviceProvider: sp,
          authConnectionId: sp.authConnectionId,
          userId: sp.userId,
          maxTSSNonceToSimulate: 4,
        });

        tb = new ThresholdKey({ serviceProvider: sp, storageLayer: torusSL, manualSync, tssKeyType: TSS_KEY_TYPE });

        // factor key needs to passed from outside of tKey
        const factorKeyPair = ecFactor.genKeyPair();
        factorKey = factorKeyPair.getPrivate();
        const factorPub = Point.fromElliptic(factorKeyPair.getPublic());
        const deviceTSSShare = ecTSS.genKeyPair().getPrivate();
        await tb.initialize({ factorPub, deviceTSSShare, deviceTSSIndex });
        const reconstructedKey = await tb.reconstructKey();
        await tb.syncLocalMetadataTransitions();

        if (tb.secp256k1Key.cmp(reconstructedKey.secp256k1Key) !== 0) {
          fail("key should be able to be reconstructed");
        }
      });

      it("should be able to serialize and deserialize", async function () {
        const serialized = JSON.stringify(tb);
        const serializedSp = JSON.stringify(tb.serviceProvider);
        const spJson = TSSTorusServiceProvider.fromJSON(JSON.parse(serializedSp));

        // we are using mocked storage layer for local testing
        // const slJson = TorusStorageLayer.fromJSON(JSON.parse(serializedTorusSL));

        const tbJson = await ThresholdKey.fromJSON(JSON.parse(serialized), {
          serviceProvider: spJson,
          storageLayer: torusSL,
          manualSync,
          tssKeyType: TSS_KEY_TYPE,
        });
        // reconstruct metdata key
        await tbJson.reconstructKey();

        // try refresh share
        await tbJson.getTSSShare(factorKey);

        const newFactorKeyPair = ecFactor.genKeyPair();
        await tbJson.addFactorPub({
          authSignatures: signatures,
          existingFactorKey: factorKey,
          newFactorPub: Point.fromElliptic(newFactorKeyPair.getPublic()),
          newTSSIndex,
          refreshShares: true,
        });

        await tbJson.getTSSShare(newFactorKeyPair.getPrivate());

        const serialized2 = JSON.stringify(tbJson);

        const tbJson2 = await ThresholdKey.fromJSON(JSON.parse(serialized2), {
          serviceProvider: sp,
          storageLayer: torusSL,
          manualSync,
          tssKeyType: TSS_KEY_TYPE,
        });

        await tbJson2.reconstructKey();

        await tbJson2.getTSSShare(factorKey);
        await tbJson2.getTSSShare(newFactorKeyPair.getPrivate());
      });
    });
  });
});
