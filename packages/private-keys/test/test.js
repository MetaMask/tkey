import { deepStrictEqual, fail } from "assert";

import { ED25519Format } from "../src/ED25519Format";
import { SECP256K1Format } from "../src/SECP256K1Format";

describe("ed25519", function () {
  it("#should create ed25519 private key if not supplied", async function () {
    const keyFormat = new ED25519Format();
    const privateKeyStore = keyFormat.createPrivateKeyStore();
    if (!privateKeyStore) {
      fail("unable to create ed25519 key");
    }
  });
  it("#should use the same ed25519 private key if supplied", async function () {
    const keyFormat = new ED25519Format();
    const privateKeyStore = keyFormat.createPrivateKeyStore(
      BigInt("0x7a3118ccdd405b2750271f51cc8fe237d9863584173aec3fa4579d40e5b4951215351c3d54ef416e49567b79c42fd985fcda60a6da9a794e4e844ac8dec47e98")
    );
    if (!privateKeyStore) {
      fail("unable to create ed25519 key");
    }
    deepStrictEqual(
      privateKeyStore.privateKey.toString(16),
      "7a3118ccdd405b2750271f51cc8fe237d9863584173aec3fa4579d40e5b4951215351c3d54ef416e49567b79c42fd985fcda60a6da9a794e4e844ac8dec47e98"
    );
  });
  it("#should not create keystore if invalid ed25519 private key supplied", async function () {
    const keyFormat = new ED25519Format();
    let errorMessage = "";
    try {
      keyFormat.createPrivateKeyStore(BigInt("0x00000000000000000000000a000aef0708ada6c5b211dc5d5303cb11dc03eb95"));
    } catch (error) {
      errorMessage = error.message;
    }
    if (errorMessage !== "Invalid Private Key") {
      fail("created a keystore using an invalid ed25519 key");
    }
  });
  it("#should not be able to validate an invalid ed25519 private key", async function () {
    // invalid private key
    const key = BigInt("0x00000000000000000000000a000aef0708ada6c5b211dc5d5303cb11dc03eb95");
    const keyFormat = new ED25519Format();
    if (keyFormat.validatePrivateKey(key)) {
      fail("validated an invalid ed25519 key");
    }
  });
  it("#should be able to validate a valid ed25519 private key", async function () {
    const keyFormat = new ED25519Format();
    const privateKey = BigInt(
      "0x99da9559e15e913ee9ab2e53e3dfad575da33b49be1125bb922e33494f4988281b2f49096e3e5dbd0fcfa9c0c0cd92d9ab3b21544b34d5dd4a65d98b878b9922"
    );
    if (!keyFormat.validatePrivateKey(privateKey)) {
      fail("not able to validate ed25519 key");
    }
  });
});

// eslint-disable-next-line mocha/max-top-level-suites
describe("secp256", function () {
  it("#should create secp256k1 private key if not supplied", async function () {
    const keyFormat = new SECP256K1Format();
    const privateKeyStore = keyFormat.createPrivateKeyStore();
    if (!privateKeyStore) {
      fail("unable to create secp256k1 key");
    }
  });
  it("#should use the same secp256k1 private key if supplied", async function () {
    const keyFormat = new SECP256K1Format();
    const privateKeyStore = keyFormat.createPrivateKeyStore(BigInt("0xc2e198c3e6fb83d36d162f5a000aef0708ada6c5b201dc5d5303cb11dc03eb95"));
    if (!privateKeyStore) {
      fail("unable to create secp256k1 key");
    }
    deepStrictEqual(privateKeyStore.privateKey.toString(16), "c2e198c3e6fb83d36d162f5a000aef0708ada6c5b201dc5d5303cb11dc03eb95");
  });
  it("#should not create keystore if invalid secp256k1 private key is supplied", async function () {
    const keyFormat = new SECP256K1Format();
    let errorMessage = "";
    try {
      keyFormat.createPrivateKeyStore(BigInt("0xfffffffffffffffffffffffffffffffffaaedce6af48a03bbfd25e8cd0364141"));
    } catch (error) {
      errorMessage = error.message;
    }
    if (errorMessage !== "Invalid Private Key") {
      fail("created a keystore using an invalid secp256k1 key");
    }
  });
  it("#should not be able to validate an invalid secp256k1 private key", async function () {
    // invalid private key
    const key = BigInt("0xffffffffffffffffffffffffffffffffbaaedce6af48a03bbfd25e8cd0364141");
    const keyFormat = new SECP256K1Format();
    if (keyFormat.validatePrivateKey(key)) {
      fail("validated an invalid secp256k1 key");
    }
  });
  it("#should be able to validate a valid secp256k1 private key", async function () {
    const keyFormat = new SECP256K1Format();
    if (!keyFormat.validatePrivateKey(BigInt("0x1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0"))) {
      fail("not able to validate secp256k1 key");
    }
  });
});
