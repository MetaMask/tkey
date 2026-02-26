import { IAuthMetadata, secp256k1, StringifiedType, stripHexPrefix, toPrivKeyEC } from "@tkey/common-types";
import { utf8ToBytes } from "@toruslabs/metadata-helpers";
import { keccak256 } from "@toruslabs/torus.js";
import BN from "bn.js";
import stringify from "json-stable-stringify";

import CoreError from "./errors";
import Metadata from "./metadata";

class AuthMetadata implements IAuthMetadata {
  metadata: Metadata;

  privKey: BN;

  constructor(metadata: Metadata, privKey?: BN) {
    this.metadata = metadata;
    this.privKey = privKey;
  }

  static fromJSON(value: StringifiedType): AuthMetadata {
    const { data, sig } = value;
    if (!data) throw CoreError.metadataUndefined();

    const m = Metadata.fromJSON(data);
    if (!m.pubKey) throw CoreError.metadataPubKeyUnavailable();

    const keyPair = secp256k1.keyFromPublic(m.pubKey.toSEC1(secp256k1));
    if (!keyPair.verify(stripHexPrefix(keccak256(utf8ToBytes(stringify(data)))), sig)) {
      throw CoreError.default("Signature not valid for returning metadata");
    }
    return new AuthMetadata(m);
  }

  toJSON(): StringifiedType {
    const data = this.metadata;

    if (!this.privKey) throw CoreError.privKeyUnavailable();
    const k = toPrivKeyEC(this.privKey);
    const sig = k.sign(stripHexPrefix(keccak256(utf8ToBytes(stringify(data)))));

    return {
      data,
      sig: sig.toDER("hex"),
    };
  }
}

export default AuthMetadata;
