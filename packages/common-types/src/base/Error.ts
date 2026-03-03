import { CustomError } from "ts-custom-error";

export interface ITkeyError extends CustomError {
  name: string;
  code: number;
  message: string;
  toString(): string;
}

export type ErrorCodes = {
  [key: number]: string;
};

export abstract class TkeyError extends CustomError implements ITkeyError {
  code: number;

  message: string;

  public constructor(code?: number, message?: string) {
    // takes care of stack and proto
    super(message);

    this.code = code;
    this.message = message || "";
    // Set name explicitly as minification can mangle class names
    Object.defineProperty(this, "name", { value: "TkeyError" });
  }

  toJSON(): ITkeyError {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
    };
  }

  toString(): string {
    return JSON.stringify(this.toJSON());
  }
}
