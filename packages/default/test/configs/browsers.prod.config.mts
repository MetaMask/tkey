import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    reporters: "verbose",
    include: ["test/**/*.test.ts"],
    testTimeout: 0,
    browser: {
      screenshotFailures: false,
      headless: true,
      provider: playwright(),
      enabled: true,
      instances: [
        { name: "Chrome", browser: "chromium" },
        { name: "Firefox", browser: "firefox" },
        { name: "Safari", browser: "webkit" },
      ],
    },
    coverage: {
      reporter: ["text"],
      provider: "istanbul",
      include: ["src/**/*.ts"],
    },
    env: {
      MOCKED: "false",
      METADATA: "https://node-1.dev-node.web3auth.io/metadata",
    },
  },
  define: {
    "process.env.MOCKED": JSON.stringify("false"),
    "process.env.METADATA": JSON.stringify("https://node-1.dev-node.web3auth.io/metadata"),
  },
});
