import { defineConfig, presetIcons, presetWind3 } from "unocss";

export default defineConfig({
  presets: [
    presetIcons({
      extraProperties: {
        width: "1.2em",
        height: "1.2em",
      },
    }),
    presetWind3(),
  ],
});
