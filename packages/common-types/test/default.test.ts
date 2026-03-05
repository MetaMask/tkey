import { generatePrivate as ecGeneratePrivate } from "@toruslabs/eccrypto";
import { bytesToHex, bytesToNumberBE, secp256k1 } from "@toruslabs/metadata-helpers";
import { describe, expect, it } from "vitest";

import { getPubKeyECC, getPubKeyPoint, Point, Polynomial, PublicPolynomial, PublicShare, Share, ShareStore, toPrivKeyECC } from "../src/base";
import {
  bigIntReplacer,
  decrypt,
  derivePubKeyXFromPolyID,
  encrypt,
  generateAddressFromPublicKey,
  generateID,
  generatePrivate,
  generatePrivateExcludingIndexes,
  isEmptyObject,
  isErrorObj,
} from "../src/utils";

const randomScalar = () => bytesToNumberBE(ecGeneratePrivate());

describe("utils", function () {
  it("generatePrivate returns 32 bytes", function () {
    const key = generatePrivate();
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it("encrypt/decrypt roundtrip", async function () {
    const priv = generatePrivate();
    const pub = getPubKeyECC(bytesToNumberBE(priv));
    const msg = new TextEncoder().encode("hello tkey");
    const encrypted = await encrypt(pub, msg);
    expect(encrypted).toHaveProperty("ciphertext");
    expect(encrypted).toHaveProperty("ephemPublicKey");
    expect(encrypted).toHaveProperty("iv");
    expect(encrypted).toHaveProperty("mac");
    const decrypted = await decrypt(priv, encrypted);
    expect(decrypted).toEqual(msg);
  });

  it("isEmptyObject", function () {
    expect(isEmptyObject({})).toBe(true);
    expect(isEmptyObject({ a: 1 })).toBe(false);
  });

  it("isErrorObj", function () {
    expect(isErrorObj(new Error("test"))).toBeTruthy();
    expect(isErrorObj("not an error")).toBeFalsy();
    expect(isErrorObj(null)).toBeFalsy();
  });

  it("bigIntReplacer converts bigints to hex strings", function () {
    const obj = JSON.parse(JSON.stringify({ val: 255n }, bigIntReplacer));
    expect(obj.val).toBe("ff");
    expect(JSON.parse(JSON.stringify({ val: "hello" }, bigIntReplacer)).val).toBe("hello");
  });

  it("generateAddressFromPublicKey returns checksum address", function () {
    const priv = generatePrivate();
    const pubUncompressed = secp256k1.getPublicKey(priv, false).slice(1);
    const address = generateAddressFromPublicKey(pubUncompressed);
    expect(address).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });

  it("generatePrivateExcludingIndexes avoids given indexes", function () {
    const result = generatePrivateExcludingIndexes([1n, 2n, 3n]);
    expect(result).toBeTypeOf("bigint");
    expect([1n, 2n, 3n]).not.toContain(result);
  });

  it("derivePubKeyXFromPolyID extracts x coordinate", function () {
    const polyID = "04abc123|04def456";
    expect(derivePubKeyXFromPolyID(polyID)).toBe("abc123");
  });

  it("generateID returns a non-empty string", function () {
    const id = generateID();
    expect(id.length).toBeGreaterThan(0);
    expect(id).toBeTypeOf("string");
  });
});

describe("keyUtils", function () {
  it("toPrivKeyECC returns 32-byte big-endian encoding", function () {
    const bytes = toPrivKeyECC(1n);
    expect(bytes.length).toBe(32);
    expect(bytes[31]).toBe(1);
    expect(bytes[0]).toBe(0);
  });

  it("getPubKeyECC returns 65-byte uncompressed public key", function () {
    const scalar = randomScalar();
    const pub = getPubKeyECC(scalar);
    expect(pub.length).toBe(65);
    expect(pub[0]).toBe(0x04);
  });

  it("getPubKeyPoint returns a valid Point", function () {
    const scalar = randomScalar();
    const point = getPubKeyPoint(scalar);
    expect(point.x).toBeTypeOf("bigint");
    expect(point.y).toBeTypeOf("bigint");
  });
});

describe("Point", function () {
  it("#should encode into elliptic format on encode", async function () {
    const secret = randomScalar();
    const point = getPubKeyPoint(secret);
    const result = point.toSEC1(true);
    expect(bytesToHex(result).slice(2)).toBe(point.x.toString(16).padStart(64, "0"));
  });

  it("#should decode into point for elliptic format compressed", async function () {
    const secret = randomScalar();
    const point = getPubKeyPoint(secret);
    const result = point.toSEC1(true);
    expect(bytesToHex(result).slice(2)).toBe(point.x.toString(16).padStart(64, "0"));
    const key = secp256k1.Point.fromHex(bytesToHex(result)).toAffine();
    expect(point.x).toBe(key.x);
    expect(point.y).toBe(key.y);
  });

  it("#should decode into point for fromSEC1", async function () {
    const secret = randomScalar();
    const point = getPubKeyPoint(secret);
    const result = point.toSEC1(true);
    expect(bytesToHex(result).slice(2)).toBe(point.x.toString(16).padStart(64, "0"));
    const key = Point.fromSEC1(bytesToHex(result));
    expect(point.x).toBe(key.x);
    expect(point.y).toBe(key.y);
  });

  it("fromScalar derives the correct public key point", function () {
    const scalar = randomScalar();
    const p1 = Point.fromScalar(scalar);
    const p2 = getPubKeyPoint(scalar);
    expect(p1.equals(p2)).toBe(true);
  });

  it("fromJSON/toJSON roundtrip", function () {
    const point = getPubKeyPoint(randomScalar());
    const json = point.toJSON();
    const restored = Point.fromJSON(json);
    expect(restored.equals(point)).toBe(true);
  });

  it("fromAffine", function () {
    const point = getPubKeyPoint(randomScalar());
    const copy = Point.fromAffine({ x: point.x, y: point.y });
    expect(copy.equals(point)).toBe(true);
  });

  it("encode('arr') produces 65-byte uncompressed key", function () {
    const point = getPubKeyPoint(randomScalar());
    const encoded = point.encode("arr");
    expect(encoded.length).toBe(65);
    expect(encoded[0]).toBe(0x04);
  });

  it("toPointHex pads to 64 chars", function () {
    const point = getPubKeyPoint(randomScalar());
    const hex = point.toPointHex();
    expect(hex.x.length).toBe(64);
    expect(hex.y.length).toBe(64);
  });

  it("equals returns false for different points", function () {
    const p1 = getPubKeyPoint(randomScalar());
    const p2 = getPubKeyPoint(randomScalar());
    expect(p1.equals(p2)).toBe(false);
  });
});

describe("Polynomial", function () {
  it("#should polyEval indexes correctly", async function () {
    const polyArr = [5n, 2n];
    const poly = new Polynomial(polyArr);
    const result = poly.polyEval(1n);
    expect(result).toBe(7n);
  });

  it("getThreshold returns polynomial length", function () {
    const poly = new Polynomial([1n, 2n, 3n]);
    expect(poly.getThreshold()).toBe(3);
  });

  it("fromJSON/toJSON roundtrip", function () {
    const poly = new Polynomial([10n, 20n, 30n]);
    const json = poly.toJSON();
    const restored = Polynomial.fromJSON(json);
    expect(restored.polynomial).toEqual(poly.polynomial);
  });

  it("generateShares produces shares that evaluate correctly", function () {
    const poly = new Polynomial([100n, 200n]);
    const shares = poly.generateShares([1n, 2n]);
    expect(shares["1"].share).toBe(poly.polyEval(1n));
    expect(shares["2"].share).toBe(poly.polyEval(2n));
  });

  it("getPublicPolynomial and getPolynomialID", function () {
    const poly = new Polynomial([randomScalar(), randomScalar()]);
    const pubPoly = poly.getPublicPolynomial();
    expect(pubPoly).toBeInstanceOf(PublicPolynomial);
    pubPoly.getPolynomialID();
    const id = poly.getPolynomialID();
    expect(id).toBeTypeOf("string");
    expect(id.length).toBeGreaterThan(0);
  });
});

describe("Share", function () {
  it("fromJSON/toJSON roundtrip", function () {
    const share = new Share(1n, 42n);
    const json = share.toJSON();
    expect(json.shareIndex).toBe("1");
    expect(json.share).toBe("2a");
    const restored = Share.fromJSON(json);
    expect(restored.shareIndex).toBe(share.shareIndex);
    expect(restored.share).toBe(share.share);
  });

  it("getPublicShare returns a PublicShare", function () {
    const scalar = randomScalar();
    const share = new Share(1n, scalar);
    const pubShare = share.getPublicShare();
    expect(pubShare).toBeInstanceOf(PublicShare);
    expect(pubShare.shareIndex).toBe(1n);
  });
});

describe("PublicShare", function () {
  it("fromJSON/toJSON roundtrip", function () {
    const point = getPubKeyPoint(randomScalar());
    const ps = new PublicShare(5n, point);
    const json = JSON.parse(JSON.stringify(ps.toJSON()));
    const restored = PublicShare.fromJSON(json);
    expect(restored.shareIndex).toBe(5n);
    expect(restored.shareCommitment.equals(point)).toBe(true);
  });
});

describe("PublicPolynomial", function () {
  it("getThreshold returns commitment count", function () {
    const points = [getPubKeyPoint(randomScalar()), getPubKeyPoint(randomScalar())];
    const pubPoly = new PublicPolynomial(points);
    expect(pubPoly.getThreshold()).toBe(2);
  });

  it("getPolynomialID returns a deterministic pipe-separated string", function () {
    const points = [getPubKeyPoint(randomScalar()), getPubKeyPoint(randomScalar())];
    const pubPoly = new PublicPolynomial(points);
    const id = pubPoly.getPolynomialID();
    expect(id).toContain("|");
    expect(pubPoly.getPolynomialID()).toBe(id);
  });

  it("fromJSON/toJSON roundtrip", function () {
    const points = [getPubKeyPoint(randomScalar()), getPubKeyPoint(randomScalar())];
    const pubPoly = new PublicPolynomial(points);
    pubPoly.getPolynomialID();
    const json = JSON.parse(JSON.stringify(pubPoly.toJSON()));
    const restored = PublicPolynomial.fromJSON(json);
    expect(restored.getThreshold()).toBe(2);
    expect(restored.getPolynomialID()).toBe(pubPoly.polynomialId);
  });
});

describe("ShareStore", function () {
  it("fromJSON/toJSON roundtrip", function () {
    const share = new Share(1n, 42n);
    const store = new ShareStore(share, "somePoly|ID");
    const json = JSON.parse(JSON.stringify(store.toJSON(), bigIntReplacer));
    expect(json.polynomialID).toBe("somePoly|ID");
    const restored = ShareStore.fromJSON(json);
    expect(restored.polynomialID).toBe(store.polynomialID);
    expect(restored.share.shareIndex).toBe(1n);
    expect(restored.share.share).toBe(42n);
  });
});
