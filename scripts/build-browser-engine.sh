#!/bin/sh
# Builds scripts/engine.browser.js (IIFE, minified) from the same TypeScript the server uses. Needs esbuild (comes with tsx).
set -e
cd "$(dirname "$0")/.."
ESB=${ESBUILD:-$(command -v esbuild || echo /opt/npm-tools/node_modules/esbuild/bin/esbuild)}
"$ESB" scripts/browser-entry.ts --bundle --minify --format=iife --platform=browser --target=es2019 --alias:node:crypto=./scripts/browser-crypto.ts --outfile=scripts/engine.browser.js --legal-comments=none
