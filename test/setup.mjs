import "dotenv/config";
import "@noble/curves/secp256k1.js";
import "@noble/curves/ed25519.js";
import "@noble/curves/utils.js";
import "@noble/curves/abstract/modular.js";
import Register from "@babel/register";
import JSDOM from "jsdom-global";

import currentPkg from "../package.json" with { type: "json" };

const runtimeVersion = currentPkg.peerDependencies["@babel/runtime"];

const nativeBtoa = globalThis.btoa;
const nativeAtob = globalThis.atob;
const NativeFormData = globalThis.FormData;

JSDOM(``, {
  url: "http://localhost",
});

globalThis.btoa = nativeBtoa;
globalThis.atob = nativeAtob;
globalThis.FormData = NativeFormData;

Register({
  presets: [["@babel/env", { bugfixes: true, targets: { node: "current" } }], "@babel/typescript"],
  plugins: [
    "@babel/plugin-syntax-bigint",
    "@babel/plugin-transform-object-rest-spread",
    "@babel/plugin-transform-class-properties",
    ["@babel/transform-runtime", { version: runtimeVersion }],
    "@babel/plugin-transform-numeric-separator",
  ],
  sourceType: "unambiguous",
  extensions: [".ts", ".js"],
});

const storeFn = {
  getItem(key) {
    return this[key];
  },
  setItem(key, value) {
    this[key] = value;
  },
  removeItem(key) {
    delete this[key];
  },
};
globalThis.localStorage = { ...storeFn };
globalThis.sessionStorage = { ...storeFn };
