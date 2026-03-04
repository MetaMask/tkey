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
    include: ["**/*.test.ts"],
    passWithNoTests: true,
  },
});
