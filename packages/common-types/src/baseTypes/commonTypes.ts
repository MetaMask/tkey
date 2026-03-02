import type { CustomAuthArgs } from "@toruslabs/customauth";

export type PubKeyType = "ecc";

// @flow
export type PolynomialID = string;

export type PolyIDAndShares = [PolynomialID, string[]];

export interface EncryptedMessage {
  ciphertext: string;
  ephemPublicKey: string;
  iv: string;
  mac: string;
}

export interface ServiceProviderArgs {
  enableLogging?: boolean;
  postboxKey?: string;
}

export interface TorusServiceProviderArgs extends ServiceProviderArgs {
  customAuthArgs: CustomAuthArgs;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type StringifiedType = Record<string, any>;

export interface ISerializable {
  toJSON(): StringifiedType;
}

export interface IPoint extends ISerializable {
  x: bigint;
  y: bigint;
  encode(enc: string, params?: unknown): Uint8Array;
}

export interface IServiceProvider extends ISerializable {
  enableLogging: boolean;

  postboxKey: bigint;

  serviceProviderName: string;

  migratableKey?: bigint | null;

  encrypt(msg: Uint8Array): Promise<EncryptedMessage>;
  decrypt(msg: EncryptedMessage): Promise<Uint8Array>;
  retrievePubKey(type: PubKeyType): Uint8Array;
  retrievePubKeyPoint(): { x: bigint; y: bigint };
  sign(msg: Uint8Array): string;
}
export type TorusStorageLayerAPIParams = {
  pub_key_X: string;
  pub_key_Y: string;
  set_data: unknown;
  signature: string;
  namespace: string;
};

export interface IStorageLayer extends ISerializable {
  storageLayerName: string;

  getMetadata<T>(params: { serviceProvider?: IServiceProvider; privKey?: bigint }): Promise<T>;

  setMetadata<T>(params: { input: T; serviceProvider?: IServiceProvider; privKey?: bigint }): Promise<{ message: string }>;

  setMetadataStream<T>(params: { input: T[]; serviceProvider?: IServiceProvider; privKey?: bigint[] }): Promise<{ message: string }>;

  acquireWriteLock(params: { serviceProvider?: IServiceProvider; privKey?: bigint }): Promise<{ status: number; id?: string }>;

  releaseWriteLock(params: { id: string; serviceProvider?: IServiceProvider; privKey?: bigint }): Promise<{ status: number }>;
}

export type TorusStorageLayerArgs = {
  enableLogging?: boolean;
  hostUrl?: string;
  serverTimeOffset?: number;
};

export type MockStorageLayerArgs = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  dataMap: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  lockMap: any;
};

export type ShareDescriptionMap = {
  [shareIndexStr: string]: string[];
};

export type FromJSONConstructor = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  fromJSON(value: StringifiedType): any;
};

export type DeviceShareDescription = { module: string; userAgent: string; dateAdded: number; customDeviceInfo?: string };

export enum KeyType {
  secp256k1 = "secp256k1",
  ed25519 = "ed25519",
}
