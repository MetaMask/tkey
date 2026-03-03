import { bigIntReplacer, IAuthMetadata, secp256k1, StringifiedType, stripHexPrefix, toPrivKeyECC } from "@tkey/common-types";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@toruslabs/metadata-helpers";
import { keccak256 } from "@toruslabs/torus.js";
import stringify from "json-stable-stringify";

import CoreError from "./errors";
import Metadata from "./metadata";

class AuthMetadata implements IAuthMetadata {
  metadata: Metadata;

  privKey: bigint;

  constructor(metadata: Metadata, privKey?: bigint) {
    this.metadata = metadata;
    this.privKey = privKey;
  }

  static fromJSON(value: StringifiedType): AuthMetadata {
    const { data, sig } = value;
    if (!data) throw CoreError.metadataUndefined();

    const m = Metadata.fromJSON(data);
    if (!m.pubKey) throw CoreError.metadataPubKeyUnavailable();

    const msgHash = hexToBytes(stripHexPrefix(keccak256(utf8ToBytes(stringify(data, { replacer: bigIntReplacer })))));
    // keep lowS: false for backward compatibility with old @tkey/core@16.0.0
    // lowS: true work for both lowS and highS signatures
    if (!secp256k1.verify(hexToBytes(sig), msgHash, m.pubKey.toSEC1(true), { prehash: false, format: "der", lowS: false })) {
      throw CoreError.default("Signature not valid for returning metadata");
    }
    return new AuthMetadata(m);
  }

  toJSON(): StringifiedType {
    const data = this.metadata;

    if (!this.privKey) throw CoreError.privKeyUnavailable();
    const msgHash = hexToBytes(stripHexPrefix(keccak256(utf8ToBytes(stringify(data, { replacer: bigIntReplacer })))));
    const sig = secp256k1.sign(msgHash, toPrivKeyECC(this.privKey), { prehash: false, format: "der" });

    return {
      data,
      sig: bytesToHex(sig),
    };
  }
}

export default AuthMetadata;
