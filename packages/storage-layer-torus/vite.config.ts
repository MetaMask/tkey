import { defineConfig } from "vite-plus";

export default defineConfig({
  pack: {
    entry: "src/index.ts",
    format: {
      esm: { outDir: "dist/lib.esm" },
      cjs: { outDir: "dist/lib.cjs" },
    },
    dts: true,
    outExtensions: () => ({ js: ".js", dts: ".d.ts" }),
    sourcemap: true,
    deps: {
      onlyBundle: false,
    },
  },
});
