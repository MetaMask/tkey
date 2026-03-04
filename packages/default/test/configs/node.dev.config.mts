import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    reporters: "verbose",
    coverage: {
      reporter: ["text"],
      provider: "istanbul",
      include: ["src/**/*.ts"],
    },
    environment: "node",
    include: ["test/**/*.test.ts"],
    passWithNoTests: true,
    testTimeout: 0,
    maxWorkers: 4,
    fileParallelism: true,
    env: {
      MOCKED: "false",
      METADATA: "http://localhost:5051",
    },
  },
});
