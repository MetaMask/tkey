import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    reporters: "verbose",
    include: ["test/**/*.test.ts"],
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
      METADATA: "http://localhost:5051",
    },
  },
  define: {
    "process.env.MOCKED": JSON.stringify("false"),
    "process.env.METADATA": JSON.stringify("http://localhost:5051"),
  },
});
