import { describe, it, expect } from "vitest";

import CoreError from "../src/errors";

describe("Errors", function () {
  it("#serialize", function () {
    expect(() => {
      throw CoreError.metadataUndefined();
    }).toThrow(CoreError);
    const err = (() => {
      try {
        throw CoreError.metadataUndefined();
      } catch (e) {
        return e as CoreError;
      }
    })();
    expect(err.code).toBe(1101);
    expect(err.message).toBe("metadata not found, SDK likely not initialized ");
  });
  it("#fromCode", function () {
    expect(() => {
      throw CoreError.fromCode(1101);
    }).toThrow(CoreError);
    const err = (() => {
      try {
        throw CoreError.fromCode(1101);
      } catch (e) {
        return e as CoreError;
      }
    })();
    expect(err.code).toBe(1101);
    expect(err.message).toBe("metadata not found, SDK likely not initialized ");
  });
});
