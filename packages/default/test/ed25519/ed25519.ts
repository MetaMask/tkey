import { randomBytes } from "crypto";

/// <reference types="node" />
import { ShareStore } from "@tkey/common-types";
import { generatePrivateBigInt } from "@tkey/core";
import { TorusServiceProvider } from "@tkey/service-provider-torus";
import { TorusStorageLayer } from "@tkey/storage-layer-torus";
import { bytesToHex } from "@toruslabs/metadata-helpers";
import { beforeEach, describe, expect, it } from "vite-plus/test";

import { TKeyDefault } from "../../src/index";

function requireShare(share: ShareStore | undefined): ShareStore {
  if (!share) throw new Error("expected share store");
  return share;
}

function requireKey(key: bigint | null): bigint {
  if (key === null) throw new Error("expected secp256k1 key");
  return key;
}

function requireSeed(seed: Uint8Array | null): Uint8Array {
  if (seed === null) throw new Error("expected ed25519 key");
  return seed;
}

export function ed25519Tests(params: { manualSync: boolean; torusSP: TorusServiceProvider; storageLayer: TorusStorageLayer }): void {
  let customSP = params.torusSP;
  const customSL = params.storageLayer;
  const { manualSync } = params;
  describe("tkey : ed25519 key", function () {
    let tb: TKeyDefault;

    beforeEach(async function () {
      customSP = new TorusServiceProvider({
        enableLogging: false,
        postboxKey: generatePrivateBigInt().toString(16),
        customAuthArgs: { baseUrl: "http://localhost:3000", web3AuthClientId: "test", network: "mainnet" },
      });
      tb = new TKeyDefault({
        serviceProvider: customSP,
        storageLayer: customSL,
        manualSync,
      });
    });

    it("should generate key for ed25519 and secp256k1", async function () {
      await tb.initialize();
      const secp = tb.secp256k1Key;
      const ed = tb.ed25519Key;
      const share = await tb.generateNewShare();

      if (manualSync) {
        await tb.syncLocalMetadataTransitions();
      }

      const newInstance = new TKeyDefault({ serviceProvider: customSP, storageLayer: customSL, manualSync });
      await newInstance.initialize();
      newInstance.inputShareStore(requireShare(share.newShareStores[share.newShareIndex.toString(16)]));
      await newInstance.reconstructKey();

      expect(requireKey(secp).toString(16)).toBe(requireKey(newInstance.secp256k1Key).toString(16));
      expect(bytesToHex(requireSeed(ed))).toBe(bytesToHex(requireSeed(newInstance.ed25519Key)));

      // should not able to reinitialize with import key
      const instance3 = new TKeyDefault({ serviceProvider: customSP, storageLayer: customSL, manualSync });
      await expect(
        instance3.initialize({ importKey: generatePrivateBigInt(), importEd25519Seed: new Uint8Array(randomBytes(32)) })
      ).rejects.toThrow();
    });

    it("should import key for ed25519", async function () {
      // Test with migratable key.
      (customSP as any).migratableKey = generatePrivateBigInt();

      const tb2 = new TKeyDefault({ serviceProvider: customSP, storageLayer: customSL, manualSync });
      const ed = randomBytes(32);
      await tb2.initialize({ importEd25519Seed: ed });

      const share = await tb2.generateNewShare();
      if (manualSync) {
        await tb2.syncLocalMetadataTransitions();
      }

      // Check exported seed = imported seed.
      {
        await tb2.reconstructKey();
        const edExported = tb2.ed25519Key;
        expect(bytesToHex(ed)).toBe(bytesToHex(requireSeed(edExported)));
      }

      const newInstance = new TKeyDefault({ serviceProvider: customSP, storageLayer: customSL, manualSync });
      await newInstance.initialize();
      const edPub = newInstance.getEd25519PublicKey();

      newInstance.inputShareStore(requireShare(share.newShareStores[share.newShareIndex.toString(16)]));
      await newInstance.reconstructKey();

      expect(bytesToHex(ed)).toBe(bytesToHex(requireSeed(newInstance.ed25519Key)));
      expect(edPub).toBe(newInstance.getEd25519PublicKey());
      // should not able to reinitialize with import key
      const instance3 = new TKeyDefault({ serviceProvider: customSP, storageLayer: customSL, manualSync });
      await expect(
        instance3.initialize({ importKey: generatePrivateBigInt(), importEd25519Seed: new Uint8Array(randomBytes(32)) })
      ).rejects.toThrow();
    });

    it("should import key for ed25519 and secp256k1", async function () {
      const tb2 = new TKeyDefault({ serviceProvider: customSP, storageLayer: customSL, manualSync });
      const secp = generatePrivateBigInt();
      const ed = randomBytes(32);
      await tb2.initialize({ importKey: secp, importEd25519Seed: ed });

      const share = await tb2.generateNewShare();
      if (manualSync) {
        await tb2.syncLocalMetadataTransitions();
      }

      const newInstance = new TKeyDefault({ serviceProvider: customSP, storageLayer: customSL, manualSync });
      await newInstance.initialize();
      const edPub = newInstance.getEd25519PublicKey();

      newInstance.inputShareStore(requireShare(share.newShareStores[share.newShareIndex.toString(16)]));
      await newInstance.reconstructKey();

      expect(secp.toString(16)).toBe(requireKey(newInstance.secp256k1Key).toString(16));
      expect(bytesToHex(ed)).toBe(bytesToHex(requireSeed(newInstance.ed25519Key)));
      expect(edPub).toBe(newInstance.getEd25519PublicKey());
      // should not able to reinitialize with import key
      const instance3 = new TKeyDefault({ serviceProvider: customSP, storageLayer: customSL, manualSync });
      await expect(
        instance3.initialize({ importKey: generatePrivateBigInt(), importEd25519Seed: new Uint8Array(randomBytes(32)) })
      ).rejects.toThrow();
    });
  });
}
