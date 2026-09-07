import globals from 'globals';
import react from 'eslint-plugin-react';

export default [{
  files: ['src/**/*.{js,jsx}'],
  ignores: ['src/**/*.test.{js,jsx}'],
  languageOptions: { ecmaVersion: 'latest', sourceType: 'module', globals: globals.browser, parserOptions: { ecmaFeatures: { jsx: true } } },
  plugins: { react },
  rules: { 'no-undef': 'error', 'react/jsx-no-undef': 'error' },
}];
