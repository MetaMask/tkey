import { describe, expect, it } from "vitest";

import { ED25519Format } from "../src/ED25519Format";
import { SECP256K1Format } from "../src/SECP256K1Format";

describe("ed25519", function () {
  it("#should create ed25519 private key if not supplied", async function () {
    const keyFormat = new ED25519Format(0n);
    const privateKeyStore = keyFormat.createPrivateKeyStore();
    expect(privateKeyStore).toBeTruthy();
  });
  it("#should use the same ed25519 private key if supplied", async function () {
    const keyFormat = new ED25519Format(0n);
    const privateKeyStore = keyFormat.createPrivateKeyStore(
      BigInt("0x7a3118ccdd405b2750271f51cc8fe237d9863584173aec3fa4579d40e5b4951215351c3d54ef416e49567b79c42fd985fcda60a6da9a794e4e844ac8dec47e98")
    );
    expect(privateKeyStore).toBeTruthy();
    expect(privateKeyStore.privateKey.toString(16)).toStrictEqual(
      "7a3118ccdd405b2750271f51cc8fe237d9863584173aec3fa4579d40e5b4951215351c3d54ef416e49567b79c42fd985fcda60a6da9a794e4e844ac8dec47e98"
    );
  });
  it("#should not create keystore if invalid ed25519 private key supplied", async function () {
    const keyFormat = new ED25519Format(0n);
    expect(() =>
      keyFormat.createPrivateKeyStore(BigInt("0x00000000000000000000000a000aef0708ada6c5b211dc5d5303cb11dc03eb95"))
    ).toThrow("Invalid Private Key");
  });
  it("#should not be able to validate an invalid ed25519 private key", async function () {
    const key = BigInt("0x00000000000000000000000a000aef0708ada6c5b211dc5d5303cb11dc03eb95");
    const keyFormat = new ED25519Format(0n);
    expect(keyFormat.validatePrivateKey(key)).toBe(false);
  });
  it("#should be able to validate a valid ed25519 private key", async function () {
    const keyFormat = new ED25519Format(0n);
    const privateKey = BigInt(
      "0x99da9559e15e913ee9ab2e53e3dfad575da33b49be1125bb922e33494f4988281b2f49096e3e5dbd0fcfa9c0c0cd92d9ab3b21544b34d5dd4a65d98b878b9922"
    );
    expect(keyFormat.validatePrivateKey(privateKey)).toBe(true);
  });
});

describe("secp256", function () {
  it("#should create secp256k1 private key if not supplied", async function () {
    const keyFormat = new SECP256K1Format(0n);
    expect(keyFormat.createPrivateKeyStore()).toBeTruthy();
  });
  it("#should use the same secp256k1 private key if supplied", async function () {
    const keyFormat = new SECP256K1Format(0n);
    const privateKeyStore = keyFormat.createPrivateKeyStore(
      BigInt("0xc2e198c3e6fb83d36d162f5a000aef0708ada6c5b201dc5d5303cb11dc03eb95")
    );
    expect(privateKeyStore).toBeTruthy();
    expect(privateKeyStore.privateKey.toString(16)).toStrictEqual(
      "c2e198c3e6fb83d36d162f5a000aef0708ada6c5b201dc5d5303cb11dc03eb95"
    );
  });
  it("#should not create keystore if invalid secp256k1 private key is supplied", async function () {
    const keyFormat = new SECP256K1Format(0n);
    expect(() =>
      keyFormat.createPrivateKeyStore(
        BigInt("0xfffffffffffffffffffffffffffffffffaaedce6af48a03bbfd25e8cd0364141")
      )
    ).toThrow("Invalid Private Key");
  });
  it("#should not be able to validate an invalid secp256k1 private key", async function () {
    const key = BigInt("0xffffffffffffffffffffffffffffffffbaaedce6af48a03bbfd25e8cd0364141");
    const keyFormat = new SECP256K1Format(0n);
    expect(keyFormat.validatePrivateKey(key)).toBe(false);
  });
  it("#should be able to validate a valid secp256k1 private key", async function () {
    const keyFormat = new SECP256K1Format(0n);
    expect(
      keyFormat.validatePrivateKey(BigInt("0x1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0"))
    ).toBe(true);
  });
});
