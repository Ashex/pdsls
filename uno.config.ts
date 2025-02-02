import { defineConfig, presetUno } from "unocss";

export default defineConfig({
  presets: [presetUno()],
  extendTheme: (theme) => {
    return {
      ...theme,
      breakpoints: {
        ...theme.breakpoints,
        xs: "400px",
      },
    };
  },
});
