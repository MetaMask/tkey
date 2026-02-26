import type { CustomAuthArgs } from "@toruslabs/customauth";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";

export type EllipticPoint = curve.base.BasePoint;
export type EllipticCurve = EC;

export type PubKeyType = "ecc";

// @flow
export type PolynomialID = string;

export type PolyIDAndShares = [PolynomialID, string[]];

export type BNString = string | BN;

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
  x: BN | null;
  y: BN | null;
  encode(enc: string, params?: unknown): Uint8Array;
}

export interface IServiceProvider extends ISerializable {
  enableLogging: boolean;

  postboxKey: BN;

  serviceProviderName: string;

  migratableKey?: BN | null;

  encrypt(msg: Uint8Array): Promise<EncryptedMessage>;
  decrypt(msg: EncryptedMessage): Promise<Uint8Array>;
  retrievePubKey(type: PubKeyType): Uint8Array;
  retrievePubKeyPoint(): EllipticPoint;
  sign(msg: BNString): string;
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

  getMetadata<T>(params: { serviceProvider?: IServiceProvider; privKey?: BN }): Promise<T>;

  setMetadata<T>(params: { input: T; serviceProvider?: IServiceProvider; privKey?: BN }): Promise<{ message: string }>;

  setMetadataStream<T>(params: { input: T[]; serviceProvider?: IServiceProvider; privKey?: BN[] }): Promise<{ message: string }>;

  acquireWriteLock(params: { serviceProvider?: IServiceProvider; privKey?: BN }): Promise<{ status: number; id?: string }>;

  releaseWriteLock(params: { id: string; serviceProvider?: IServiceProvider; privKey?: BN }): Promise<{ status: number }>;
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
