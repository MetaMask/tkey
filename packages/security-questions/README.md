# tKey Security Questions Module

[![npm version](https://img.shields.io/npm/v/@tkey/security-questions?label=%22%22)](https://www.npmjs.com/package/@tkey/security-questions/v/latest) [![minzip](https://img.shields.io/bundlephobia/minzip/@tkey/security-questions?label=%22%22)](https://bundlephobia.com/result?p=@tkey/security-questions@latest)

The tKey Security Questions Module helps you add or remove the and password as a share for tkey. This module is the part of the [tKey SDK](https://github.com/tkey/tkey/).

## Installation

```shell
npm install --save @tkey/security-questions
```

## Initialization

#### Import the `SecurityQuestionsModule` class from `@tkey/security-questions`

```javascript
import SecurityQuestionsModule from "@tkey/security-questions";
```

#### Assign the `SecurityQuestionsModule` class to a variable

```javascript
const securityQuestionsModule = new SecurityQuestionsModule(params);
```

### Parameters

`params`

- `saveAnswers?`: `boolean`

### Returns

The `SecurityQuestionsModule` class returns an object with the following properties:

```ts
class SecurityQuestionsModule implements IModule {
  moduleName: string;
  tbSDK: ITKeyApi;
  saveAnswers: boolean;
  constructor(saveAnswers?: boolean);
  static refreshSecurityQuestionsMiddleware(generalStore: unknown, oldShareStores: ShareStoreMap, newShareStores: ShareStoreMap): unknown;
  setModuleReferences(tbSDK: ITKeyApi): void;
  initialize(): Promise<void>;
  generateNewShareWithSecurityQuestions(answerString: string, questions: string): Promise<GenerateNewShareResult>;
  getSecurityQuestions(): string;
  inputShareFromSecurityQuestions(answerString: string): Promise<void>;
  changeSecurityQuestionAndAnswer(newAnswerString: string, newQuestions: string): Promise<void>;
  saveAnswerOnTkeyStore(answerString: string): Promise<void>;
  getAnswer(): Promise<string>;
}
```

## Usage

With the `SecurityQuestionsModule`, you've access to the following functions:

### Generate new share with security questions

#### `generateNewShareWithSecurityQuestions(answerString: string, questions: string)`

- `answerString`: Answer corresponding to a security question
- `questions`: The secutity question

#### Return

- `Promise<GenerateNewShareResult>`: The `GenerateNewShareResult` object

##### GenerateNewShareResult

```ts
declare type GenerateNewShareResult = {
  newShareStores: ShareStoreMap;
  newShareIndex: BN;
};
export declare type ShareStoreMap = {
  [shareIndex: string]: ShareStore;
};
declare class ShareStore implements ISerializable {
  share: Share;
  polynomialID: PolynomialID;
  constructor(share: Share, polynomialID: PolynomialID);
  static fromJSON(value: StringifiedType): ShareStore;
  toJSON(): StringifiedType;
}
```

### Get Security Question

#### `getSecurityQuestions()`

#### Return

- `string`: The security question

### Input share from security question

#### `inputShareFromSecurityQuestions(answerString: string)`

- `answerString`: Answer corresponding to the security question

### Change Security Question and Answer

#### `changeSecurityQuestionAndAnswer(newAnswerString: string, newQuestions: string)`

- `newAnswerString`: Answer corresponding to the new security question
- `newQuestions`: The new secutity question

### Save answer on tkey store

#### `saveAnswerOnTkeyStore(answerString: string)`

- `answerString`: Answer corresponding to the security question

### Get answer

#### `getAnswer`

#### Return

- `string`: The answer corresponding to the security question
