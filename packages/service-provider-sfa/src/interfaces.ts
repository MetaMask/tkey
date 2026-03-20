import { type ServiceProviderArgs } from "@tkey/common-types";
import { BUILD_ENV_TYPE, type TORUS_NETWORK_TYPE } from "@toruslabs/constants";

export interface Web3AuthOptions {
  clientId: string;
  network: TORUS_NETWORK_TYPE;
  /**
   * Set this flag to false to generate keys on client side
   * by default keys are generated on using dkg protocol on a distributed network
   * @defaultValue undefined
   */
  useDkg?: boolean;
  buildEnv?: BUILD_ENV_TYPE;
}
export interface SfaServiceProviderArgs extends ServiceProviderArgs {
  web3AuthOptions: Web3AuthOptions;
}

export type VerifierParams = {
  verify_params?: {
    verifier_id: string;
    idtoken: string;
  }[];
  sub_verifier_ids?: string[];
  verifier_id: string;
};

export type LoginParams = {
  authConnectionId: string;
  userId: string;
  idToken: string;
  groupedAuthConnectionId?: string;
  // offset in seconds
  serverTimeOffset?: number;
};
