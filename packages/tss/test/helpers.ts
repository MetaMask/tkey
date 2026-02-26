import { IStorageLayer, KeyType } from "@tkey/common-types";
import { MockStorageLayer, TorusStorageLayer } from "@tkey/storage-layer-torus";
import { getEd25519ExtendedPublicKey as getEd25519KeyPairFromSeed, getKeyCurve, Torus } from "@toruslabs/torus.js";
import BN from "bn.js";
import { KJUR } from "jsrsasign";

import { TSSTorusServiceProvider } from "../src";

const { METADATA } = process.env;

export function initStorageLayer(): IStorageLayer {
  return METADATA === "mocked" ? new MockStorageLayer() : new TorusStorageLayer({ hostUrl: METADATA });
}

function generateIdToken(email: string): string {
  const privKey = `-----BEGIN PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCD7oLrcKae+jVZPGx52Cb/lKhdKxpXjl9eGNa1MlY57A==\n-----END PRIVATE KEY-----`;
  const alg = "ES256";
  const iat = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "torus-key-test",
    aud: "torus-key-test",
    name: email,
    email,
    scope: "email",
    iat,
    eat: iat + 120,
  };

  const options = {
    expiresIn: "120",
    algorithm: alg,
  };

  const header = { alg, typ: "JWT" };

  const token = KJUR.jws.JWS.sign(alg, header, payload, privKey, options);

  return token;
}

export async function fetchPostboxKeyAndSigs(opts: { serviceProvider: TSSTorusServiceProvider; authConnectionId: string; userId: string }) {
  const { serviceProvider, authConnectionId: verifier, userId: verifierId } = opts;

  const nodeDetails = await serviceProvider.customAuthInstance.nodeDetailManager.getNodeDetails({ verifier, verifierId });
  const token = generateIdToken(verifierId);

  const tKey = await serviceProvider.customAuthInstance.torus.retrieveShares({
    endpoints: nodeDetails.torusNodeEndpoints,
    indexes: nodeDetails.torusIndexes,
    verifier,
    verifierParams: { verifier_id: verifierId },
    idToken: token,
    nodePubkeys: nodeDetails.torusNodePub,
  });

  const signatures = tKey.sessionData.sessionTokenData.map((session) => JSON.stringify({ data: session.token, sig: session.signature }));

  const localPrivKey = Torus.getPostboxKey(tKey);
  return {
    signatures,
    postboxkey: new BN(localPrivKey, "hex"),
  };
}

// This function is only for testing and will return tss shares only for test verifiers.
export async function assignTssDkgKeys(opts: {
  serviceProvider: TSSTorusServiceProvider;
  authConnectionId: string;
  userId: string;
  maxTSSNonceToSimulate: number;
  tssTag?: string;
}) {
  const { serviceProvider, authConnectionId: verifier, userId: verifierId } = opts;

  let { tssTag, maxTSSNonceToSimulate } = opts;
  tssTag = tssTag || "default";
  maxTSSNonceToSimulate = maxTSSNonceToSimulate || 1;
  // set tssShares on servers
  const serverDKGPrivKeys = [];
  // const serverDKGPubKeys = [];

  for (let j = 0; j < maxTSSNonceToSimulate; j++) {
    const token = generateIdToken(verifierId);
    const extendedVerifierId = `${verifierId}\u0015${tssTag}\u0016${j}`;

    const nodeDetails = await serviceProvider.customAuthInstance.nodeDetailManager.getNodeDetails({ verifier, verifierId });

    const tKey = await serviceProvider.customAuthInstance.torus.retrieveShares({
      endpoints: nodeDetails.torusNodeEndpoints,
      indexes: nodeDetails.torusIndexes,
      verifier,
      verifierParams: { verifier_id: verifierId, extended_verifier_id: extendedVerifierId },
      idToken: token,
      nodePubkeys: nodeDetails.torusNodePub,
    });
    const localPrivKey = tKey.oAuthKeyData.privKey;

    serverDKGPrivKeys.push(new BN(localPrivKey, "hex"));
  }

  return {
    serverDKGPrivKeys,
  };
}

export function generateKey(keyType: KeyType): {
  raw: Uint8Array;
  scalar: BN;
} {
  if (keyType === KeyType.secp256k1) {
    const scalar = new BN(getKeyCurve(keyType).keygen().secretKey);
    return {
      raw: new Uint8Array(scalar.toArrayLike(Buffer, "be", 32)),
      scalar,
    };
  } else if (keyType === KeyType.ed25519) {
    const raw = new Uint8Array(32);
    crypto.getRandomValues(raw);
    const { scalar } = getEd25519KeyPairFromSeed(raw);
    return {
      raw,
      scalar: new BN(scalar.toString(16), 16),
    };
  }
  throw new Error("unsupported key type");
}
