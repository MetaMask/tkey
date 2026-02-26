import { type StringifiedType } from "@tkey/common-types";
import { ServiceProviderBase } from "@tkey/service-provider-base";
import { NodeDetailManager } from "@toruslabs/fetch-node-details";
import { utf8ToBytes } from "@toruslabs/metadata-helpers";
import { keccak256, Torus, TorusKey } from "@toruslabs/torus.js";
import BN from "bn.js";

import { LoginParams, SfaServiceProviderArgs, VerifierParams, Web3AuthOptions } from "./interfaces";

class SfaServiceProvider extends ServiceProviderBase {
  web3AuthOptions: Web3AuthOptions;

  authInstance: Torus;

  public torusKey: TorusKey;

  public migratableKey: BN | null = null; // Migration of key from SFA to tKey

  private nodeDetailManagerInstance: NodeDetailManager;

  constructor({ enableLogging = false, postboxKey, web3AuthOptions }: SfaServiceProviderArgs) {
    super({ enableLogging, postboxKey });
    this.web3AuthOptions = web3AuthOptions;
    this.authInstance = new Torus({
      clientId: web3AuthOptions.clientId,
      enableOneKey: true,
      network: web3AuthOptions.network,
    });
    Torus.enableLogging(enableLogging);
    this.serviceProviderName = "SfaServiceProvider";
    this.nodeDetailManagerInstance = new NodeDetailManager({ network: web3AuthOptions.network, enableLogging });
  }

  static fromJSON(value: StringifiedType): SfaServiceProvider {
    const { enableLogging, postboxKey, web3AuthOptions, serviceProviderName, torusKey } = value;
    if (serviceProviderName !== "SfaServiceProvider") return undefined;

    const sfaSP = new SfaServiceProvider({
      enableLogging,
      postboxKey,
      web3AuthOptions,
    });

    sfaSP.torusKey = torusKey;

    return sfaSP;
  }

  async connect(params: LoginParams): Promise<BN> {
    const { authConnectionId, userId, idToken, groupedAuthConnectionId } = params;
    const verifier = groupedAuthConnectionId || authConnectionId;
    const verifierId = userId;
    const verifierParams: VerifierParams = { verifier_id: userId };
    let aggregateIdToken = "";
    const finalIdToken = idToken;

    if (groupedAuthConnectionId) {
      verifierParams["verify_params"] = [{ verifier_id: userId, idtoken: finalIdToken }];
      verifierParams["sub_verifier_ids"] = [authConnectionId];
      aggregateIdToken = keccak256(utf8ToBytes(finalIdToken)).slice(2);
    }
    // fetch node details.
    const { torusNodeEndpoints, torusIndexes, torusNodePub } = await this.nodeDetailManagerInstance.getNodeDetails({ verifier, verifierId });

    if (params.serverTimeOffset) {
      this.authInstance.serverTimeOffset = params.serverTimeOffset;
    }

    const torusKey = await this.authInstance.retrieveShares({
      endpoints: torusNodeEndpoints,
      indexes: torusIndexes,
      verifier: verifier,
      verifierParams: verifierParams,
      idToken: aggregateIdToken || finalIdToken,
      nodePubkeys: torusNodePub,
      useDkg: this.web3AuthOptions.useDkg,
    });
    this.torusKey = torusKey;

    if (!torusKey.metadata.upgraded) {
      const { finalKeyData, oAuthKeyData } = torusKey;
      const privKey = finalKeyData.privKey || oAuthKeyData.privKey;
      this.migratableKey = new BN(privKey, "hex");
    }
    const postboxKey = Torus.getPostboxKey(torusKey);
    this.postboxKey = new BN(postboxKey, 16);
    return this.postboxKey;
  }

  toJSON(): StringifiedType {
    return {
      ...super.toJSON(),
      serviceProviderName: this.serviceProviderName,
      web3AuthOptions: this.web3AuthOptions,
    };
  }
}

export default SfaServiceProvider;
