import { Point, StringifiedType } from "@tkey/common-types";
import { TorusServiceProvider } from "@tkey/service-provider-torus";
import { CustomAuthLoginParams, TorusLoginResponse } from "@toruslabs/customauth";
import { PointHex } from "@toruslabs/rss-client";

import { getExtendedVerifierId } from "./util";

export class TSSTorusServiceProvider extends TorusServiceProvider {
  authConnectionId?: string;

  userId?: string;

  static fromJSON(value: StringifiedType): TSSTorusServiceProvider {
    const { enableLogging, postboxKey, customAuthArgs, authConnectionId, userId } = value;
    const serviceProvider = new TSSTorusServiceProvider({
      enableLogging,
      postboxKey,
      customAuthArgs,
    });

    serviceProvider.userId = userId;
    serviceProvider.authConnectionId = authConnectionId;

    return serviceProvider;
  }

  toJSON(): StringifiedType {
    return {
      enableLogging: this.enableLogging,
      postboxKey: this.postboxKey,
      customAuthArgs: this.customAuthArgs,
      authConnectionId: this.authConnectionId,
      userId: this.userId,
    };
  }

  async getRSSNodeDetails(): Promise<{ serverEndpoints: string[]; serverPubKeys: PointHex[]; serverThreshold: number }> {
    if (!this.userId) throw new Error("no userId, not logged in");
    if (!this.authConnectionId) throw new Error("no authConnectionId, not logged in");

    const { torusNodeRSSEndpoints: tssNodeEndpoints, torusNodePub: torusPubKeys } = await this.customAuthInstance.nodeDetailManager.getNodeDetails({
      verifier: this.authConnectionId,
      verifierId: this.userId,
    });

    return {
      serverEndpoints: tssNodeEndpoints,
      serverPubKeys: torusPubKeys.map((key) => {
        return {
          x: key.X,
          y: key.Y,
        };
      }),
      serverThreshold: Math.ceil(tssNodeEndpoints.length / 2),
    };
  }

  async getTSSPubKey(
    tssTag: string,
    tssNonce: number
  ): Promise<{
    pubKey: Point;
    nodeIndexes?: number[];
  }> {
    if (!this.authConnectionId || !this.userId) throw new Error("verifier userinfo not found, not logged in yet");

    const nodeDetails = await this.customAuthInstance.nodeDetailManager.getNodeDetails({ verifier: this.authConnectionId, verifierId: this.userId });
    const tssServerPub = await this.customAuthInstance.torus.getPublicAddress(nodeDetails.torusNodeSSSEndpoints, nodeDetails.torusNodePub, {
      verifier: this.authConnectionId,
      verifierId: this.userId,
      extendedVerifierId: getExtendedVerifierId(this.userId, tssTag, tssNonce),
    });

    return {
      pubKey: new Point(BigInt(`0x${tssServerPub.finalKeyData.X}`), BigInt(`0x${tssServerPub.finalKeyData.Y}`)),
      nodeIndexes: tssServerPub.nodesData.nodeIndexes || [],
    };
  }

  getVerifierNameVerifierId(): string {
    return `${this.authConnectionId}\u001c${this.userId}`;
  }

  async triggerLogin(params: CustomAuthLoginParams): Promise<TorusLoginResponse> {
    const obj = await super.triggerLogin(params);

    if (obj) {
      const { authConnectionId, userId } = obj.userInfo;
      this.authConnectionId = authConnectionId;
      this.userId = userId;
    }

    return obj;
  }
}
