// eslint-disable-next-line import/no-unresolved
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    reporters: "verbose",
    environment: "node",
    include: ["test/**/*.js"],
  },
});
