# Runtime compatibility

Checked 2026-11-25 for issue #58. The package is CommonJS (`main: src/index.js`,
no `"type"` field in `package.json`).

## Node (baseline)

- Version: Node v24.22.1
- Command: `npm test` (runs `node --test`)
- Result: **146 passed, 0 failed.**

## Bun

- Version: Bun 1.4.4
- `require` load: works — `require('./src/index.js')` then
  `redact('Contact me at alice@example.com')` returns `Contact me at [EMAIL]`.
- `import` load: works — `import { redact } from './src/index.js'` gives the same result.
- Basic redaction: email → `[EMAIL]`; a token with an `sbp_` prefix →
  `<redacted>`; a card number → `[CARD]`.
  (Test values were placeholders / repeated filler characters, never real secrets.)
- Test suite: `bun test test/` → **146 passed, 0 failed** (2 files).

## Deno

- Version: Deno 2.9.8 (installed 2026-11-25 with the official installer,
  `curl -fsSL https://deno.land/install.sh | sh`, to `~/.deno/bin/deno`).
- `require` load: works via `createRequire` from `node:module`.
- `import` load **without extra flags: fails.**
  `import { redact } from './src/index.js'` throws
  `SyntaxError: The requested module ... does not provide an export named 'redact'`.
  Deno treats `src/index.js` as ESM because `package.json` has no
  `"type": "commonjs"`, so it never detects the CommonJS `module.exports`.
- With the flag: `deno run --allow-read --unstable-detect-cjs <file>` — import
  works and redaction works (email → `[EMAIL]`, token → `<redacted>`).
- Test suite: `deno test --allow-read --unstable-detect-cjs test/redact.test.js`
  → **141 passed, 0 failed.**
  `deno test --allow-read --unstable-detect-cjs --no-check test/` →
  **146 passed, 0 failed.**
- Note: `deno test` with type-checking on `test/types.test.ts` fails before
  running, because Deno cannot resolve `npm:@types/node` in this checkout.
  That is a test-environment quirk, not a package runtime problem — the same
  file passes with `--no-check`, and Node strips its types natively.

## Known gap (for a follow-up issue, not fixed here)

- The package does not load under plain Deno with no flags: `package.json`
  has no `"type": "commonjs"`, so Deno reads `src/index.js` as ESM and the
  named exports are missing. Adding `"type": "commonjs"` (or shipping the
  entry as `.cjs`) should make Deno detect the CommonJS module without the
  `--unstable-detect-cjs` flag. Bun and Node are unaffected either way.
