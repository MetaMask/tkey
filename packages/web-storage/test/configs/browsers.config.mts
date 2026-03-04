import { playwright } from "@vitest/browser-playwright";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    reporters: "verbose",
    environment: "node",
    include: ["test/**/*.js"],
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
  },
  define: {
    "process.env.MOCKED": JSON.stringify(process.env.MOCKED ?? "false"),
    "process.env.METADATA": JSON.stringify(process.env.METADATA ?? ""),
  },
});
