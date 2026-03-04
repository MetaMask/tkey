// eslint-disable-next-line import/no-unresolved
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    reporters: "verbose",
    environment: "node",
    include: ["test/**/*.test.ts"],
    testTimeout: 0,
    maxWorkers: 4,
    fileParallelism: true,
    coverage: {
      reporter: ["text"],
      provider: "istanbul",
      include: ["src/**/*.ts"],
    },
  },
});
