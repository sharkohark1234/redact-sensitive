# Runtime compatibility

Checked 2026-11-25 for issue #58, re-checked 2026-11-25 after the fix for
issue #76, re-checked 2026-11-26 after the Notion and Figma token patterns
landed. The package is CommonJS (`main: src/index.js`,
`"type": "commonjs"` in `package.json`).

## Node (baseline)

- Version: Node v24.22.1
- Command: `npm test` (runs `node --test`)
- Result: **153 passed, 0 failed.**

## Bun

- Version: Bun 1.4.4
- `require` load: works — `require('./src/index.js')` then
  `redact('Contact me at alice@example.com')` returns `Contact me at [EMAIL]`.
- `import` load: works — `import { redact } from './src/index.js'` gives the same result.
- Basic redaction: email → `[EMAIL]`; a token with an `sbp_` prefix →
  `<redacted>`; a card number → `[CARD]`.
  (Test values were placeholders / repeated filler characters, never real secrets.)
- Test suite: `bun test test/` → **153 passed, 0 failed** (2 files).

## Deno

- Version: Deno 2.9.8 (installed 2026-11-25 with the official installer,
  `curl -fsSL https://deno.land/install.sh | sh`, to `~/.deno/bin/deno`).
- `require` load: works via `createRequire` from `node:module`.
- `import` load **without extra flags: works** (fixed by #76 — adding
  `"type": "commonjs"` to `package.json`).
  `import { redact } from './src/index.js'` then
  `redact('Contact ana@example.com')` returns `Contact [EMAIL]`.
  Verified 2026-11-25 with Deno 2.9.8; the same import failed before the
  fix with `SyntaxError: The requested module ... does not provide an export
  named 'redact'`.
- Test suite: `deno test --allow-read --unstable-detect-cjs test/redact.test.js`
  → **148 passed, 0 failed.**
  `deno test --allow-read --unstable-detect-cjs --no-check test/` →
  **153 passed, 0 failed.**
- Note: `deno test` with type-checking on `test/types.test.mts` fails before
  running, because Deno cannot resolve `npm:@types/node` in this checkout.
  That is a test-environment quirk, not a package runtime problem — the same
  file passes with `--no-check`, and Node strips its types natively.

## Known gap (fixed by #76)

- Plain Deno import used to fail because `package.json` had no `"type"`
  field. Adding `"type": "commonjs"` fixed it (see the Deno section above);
  the `--unstable-detect-cjs` flag is no longer needed. `test/types.test.mts`
  now uses ESM imports (it is `.mts` so it loads as ESM under both Node and
  Deno) so `npm test` and `deno test --no-check test/` both pass.
