import { IAuthMetadata, secp256k1, StringifiedType, stripHexPrefix, toPrivKeyECC } from "@tkey/common-types";
import { utf8ToBytes } from "@toruslabs/metadata-helpers";
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

    const msgHash = stripHexPrefix(keccak256(utf8ToBytes(stringify(data))));
    if (!secp256k1.verify(sig, msgHash, m.pubKey.toSEC1(), { prehash: false, format: "der" })) {
      throw CoreError.default("Signature not valid for returning metadata");
    }
    return new AuthMetadata(m);
  }

  toJSON(): StringifiedType {
    const data = this.metadata;

    if (!this.privKey) throw CoreError.privKeyUnavailable();
    const msgHash = stripHexPrefix(keccak256(utf8ToBytes(stringify(data))));
    const sig = secp256k1.sign(msgHash, toPrivKeyECC(this.privKey), { prehash: false });

    return {
      data,
      sig: sig.toHex("der"),
    };
  }
}

export default AuthMetadata;
