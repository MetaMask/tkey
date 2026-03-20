import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@toruslabs/metadata-helpers";

import ShareSerializationError from "./errors";

export function normalize(str?: string): string {
  return (str || "").normalize("NFKD");
}

export function binaryToByte(bin: string): number {
  return parseInt(bin, 2);
}

export function lpad(str: string, padString: string, length: number): string {
  let string = str;
  while (string.length < length) {
    string = padString + string;
  }
  return string;
}

export function bytesToBinary(bytes: number[]): string {
  return bytes.map((x) => lpad(x.toString(2), "0", 8)).join("");
}

export function deriveChecksumBits(entropy: Uint8Array): string {
  const ENT = entropy.length * 8;
  const CS = ENT / 32;
  const hash = sha256(entropy);

  return bytesToBinary(Array.from(hash)).slice(0, CS);
}

export function entropyToMnemonic(entropy: Uint8Array | string, english: string[]): string {
  let newEntropy: Uint8Array;
  if (typeof entropy === "string") {
    newEntropy = hexToBytes(entropy);
  } else {
    newEntropy = entropy;
  }

  // 128 <= ENT <= 256
  if (newEntropy.length < 16) {
    throw ShareSerializationError.invalidEntropy();
  }
  if (newEntropy.length > 32) {
    throw ShareSerializationError.invalidEntropy();
  }
  if (newEntropy.length % 4 !== 0) {
    throw ShareSerializationError.invalidEntropy();
  }

  const entropyBits = bytesToBinary(Array.from(newEntropy));
  const checksumBits = deriveChecksumBits(newEntropy);

  const bits = entropyBits + checksumBits;
  const chunks = bits.match(/(.{1,11})/g);
  const words = chunks.map((binary: string): string => {
    const index = binaryToByte(binary);
    return english[index];
  });

  return english[0] === "\u3042\u3044\u3053\u304f\u3057\u3093" // Japanese wordlist
    ? words.join("\u3000")
    : words.join(" ");
}

export function mnemonicToEntropy(mnemonic: string, english: string[]): string {
  const words = normalize(mnemonic).split(" ");
  if (words.length % 3 !== 0) {
    throw ShareSerializationError.invalidMnemonic();
  }

  // convert word indices to 11 bit binary strings
  const bits = words
    .map((word: string): string => {
      const index = english.indexOf(word);
      if (index === -1) {
        throw ShareSerializationError.invalidMnemonic();
      }

      return lpad(index.toString(2), "0", 11);
    })
    .join("");

  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropyBits = bits.slice(0, dividerIndex);
  const checksumBits = bits.slice(dividerIndex);

  // calculate the checksum and compare
  const entropyBytes = entropyBits.match(/(.{1,8})/g).map(binaryToByte);
  if (entropyBytes.length < 16) {
    throw ShareSerializationError.invalidEntropy();
  }
  if (entropyBytes.length > 32) {
    throw ShareSerializationError.invalidEntropy();
  }
  if (entropyBytes.length % 4 !== 0) {
    throw ShareSerializationError.invalidEntropy();
  }

  const entropy = new Uint8Array(entropyBytes);
  const newChecksum = deriveChecksumBits(entropy);
  if (newChecksum !== checksumBits) {
    throw ShareSerializationError.invalidChecksum();
  }

  return bytesToHex(entropy);
}
