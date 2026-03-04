// eslint-disable-next-line import/no-unresolved
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    reporters: "verbose",
    environment: "node",
    include: ["test/**/*.js"],
  },
  define: {
    "process.env.MOCKED": JSON.stringify(process.env.MOCKED ?? "false"),
    "process.env.METADATA": JSON.stringify(process.env.METADATA ?? ""),
  },
});
