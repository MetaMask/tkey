import { typescriptLintPreset } from "@toruslabs/oxlint-config-typescript";
import { formatPreset } from "@toruslabs/torus-scripts/fmt";
import { defineConfig } from "vite-plus";

export default defineConfig({
  fmt: formatPreset(),
  lint: typescriptLintPreset(),
});
