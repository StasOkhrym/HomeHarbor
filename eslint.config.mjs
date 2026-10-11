import js from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: [
      "**/*.min.js",
      "**/vendor/**",
      "**/generated/**",
      ".local/**",
      ".superpowers/**",
      "apps/**",
    ],
  },
  {
    files: ["**/*.{js,mjs,cjs}"],
    ignores: ["internal/web/assets/static/**"],
    ...js.configs.recommended,
    languageOptions: { globals: globals.node },
  },
  {
    files: ["internal/web/assets/static/**/*.js"],
    ...js.configs.recommended,
    languageOptions: { sourceType: "script", globals: globals.browser },
  },
];
