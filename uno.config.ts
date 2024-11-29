import { defineConfig, presetIcons, presetUno } from "unocss";

export default defineConfig({
  presets: [presetIcons(), presetUno()],
  rules: [["list-dash", { "list-style-type": "'- '" }]],
});
