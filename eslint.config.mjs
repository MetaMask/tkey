import toruslabsTypescript from "@toruslabs/eslint-config-typescript";

export default [
  ...toruslabsTypescript,
  {
    languageOptions: {
      globals: {
        atob: true,
        btoa: true,
        document: true,
        fetch: true,
        jest: true,
        it: true,
        beforeEach: true,
        afterEach: true,
        describe: true,
        expect: true,
        chrome: true,
        FileSystem: true,
        FileEntry: true,
      },
    },
  },
  {
    files: ["**/test/**/*.js", "**/test/**/*.ts", "**/test/**/*.mts"],
    rules: {
      "import/no-extraneous-dependencies": "off",
      "prefer-arrow-callback": "off",
      "func-names": "off",
      "@typescript-eslint/explicit-module-boundary-types": "off",
    },
  },
];
