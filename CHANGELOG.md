# Changelog

All notable changes to redact-sensitive are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]
- Fixed Deno testing environment to support native type-checking. The Deno test command is now simply `deno test --allow-read --unstable-detect-cjs test/` without the `--no-check` flag.
  ([#82](https://github.com/sharkohark1234/redact-sensitive/issues/82)).

### Added

- npm access tokens (`npm_…`) are now redacted as `[TOKEN]`
  ([#18](https://github.com/sharkohark1234/redact-sensitive/issues/18)).
- Notion API tokens (`ntn_…`, `secret_…`) are now redacted as `[TOKEN]`
  ([#78](https://github.com/sharkohark1234/redact-sensitive/issues/78)).
- Figma personal access tokens (`figd_…`) are now redacted as `[TOKEN]`
  ([#79](https://github.com/sharkohark1234/redact-sensitive/issues/79)).
- Runtime compatibility note (`docs/compatibility.md`): verified under Node
  (156 tests pass), Bun 1.4.4 (156 tests pass) and Deno 2.9.8 (last
  verified); re-checked 2026-11-27
  ([#58](https://github.com/sharkohark1234/redact-sensitive/issues/58)).
- Anthropic API keys (`sk-ant-api03-…`, `sk-ant-admin01-…`) are now redacted
  as `[API_KEY]`
  ([#74](https://github.com/sharkohark1234/redact-sensitive/issues/74)).
- Supabase access tokens (`sbp_`, `sbp_oauth_`, `sbp_v0_`) are now redacted
  as `[TOKEN]` ([#49](https://github.com/sharkohark1234/redact-sensitive/issues/49)).
- DigitalOcean personal access, OAuth access and refresh tokens (`dop_v1_`,
  `doo_v1_`, `dor_v1_`) are now redacted as `[TOKEN]`
  ([#46](https://github.com/sharkohark1234/redact-sensitive/issues/46)).
- GitLab access tokens using the default `glpat-` prefix are now redacted
  as `[TOKEN]` ([#47](https://github.com/sharkohark1234/redact-sensitive/issues/47)).
- Hugging Face user and organisation tokens (`hf_…`) are now redacted as
  `[TOKEN]`
  ([#50](https://github.com/sharkohark1234/redact-sensitive/issues/50)).
- Benchmark script: `npm run bench` times `redact()` and
  `findSensitive()` over a 10,000-line synthetic log
  ([#57](https://github.com/sharkohark1234/redact-sensitive/issues/57)).
- The benchmark script now fails loudly when redaction breaks: it asserts
  the redacted output contains no `@example.com` or `4111 1111 1111 1111`
  and that `findSensitive()` found matches
  ([#67](https://github.com/sharkohark1234/redact-sensitive/issues/67)).
- Stripe secret keys (`sk_live_...`, `sk_test_...`) are now redacted as
  `[API_KEY]` ([#17](https://github.com/sharkohark1234/redact-sensitive/issues/17)).
- `aws_secret_access_key` and `secret_access_key` values are now redacted by
  the `key = value` pattern
  ([#20](https://github.com/sharkohark1234/redact-sensitive/issues/20)).
- `ENCRYPTED PRIVATE KEY` blocks and truncated PEM blocks with no `END` line
  are now redacted as `[PRIVATE_KEY]`
  ([#21](https://github.com/sharkohark1234/redact-sensitive/issues/21)).
- Passwords in database, cache and queue connection strings (`mongodb://`,
  `mongodb+srv://`, `postgres://`, `mysql://`, `redis://`, `amqp://`) are
  now redacted as `[PASSWORD]`, keeping the scheme, user and host readable.
  This covers the no-username form (`redis://:pass@host`) and passwords
  containing `@` or other special characters.
- Sentry DSNs are now redacted as `[DSN]` (only the public key; the ingest
  host and project id stay readable) instead of being mangled by the email
  pattern ([#55](https://github.com/sharkohark1234/redact-sensitive/issues/55)).
- GitHub fine-grained personal access tokens (`github_pat_...`) are now
  redacted as `[TOKEN]`
  ([#36](https://github.com/sharkohark1234/redact-sensitive/issues/36)).
- Slack incoming webhook URLs (`https://hooks.slack.com/services/...`,
  including GovSlack) are now redacted as `[WEBHOOK]`
  ([#52](https://github.com/sharkohark1234/redact-sensitive/issues/52)).
- Session cookie values in `Cookie` / `Set-Cookie` headers are now redacted
  as `[TOKEN]` for known session cookie names only
  ([#56](https://github.com/sharkohark1234/redact-sensitive/issues/56)).
- Mailchimp API keys (`<32 hex>-us<1-2 digits>`) are now redacted as
  `[API_KEY]`; a bare 32-character hex string is left untouched
  ([#44](https://github.com/sharkohark1234/redact-sensitive/issues/44)).
- CI now runs `npm test` on Node 16, 20 and 22 plus ESM (`.mjs`) and CJS
  (`.cjs`) smoke scripts, so a change breaking one loading style fails in
  CI instead of in a user's app
  ([#59](https://github.com/sharkohark1234/redact-sensitive/issues/59)).
- Added an interactive playground page (`docs/playground.html`) that
  redacts text live in the browser using the library source directly,
  with no build step and no network calls; the landing page now links
  to it ([#61](https://github.com/sharkohark1234/redact-sensitive/issues/61)).

### Fixed

- The TypeScript types test runs under Deno again: it moved from
  `test/types.test.ts` (CommonJS `require()`, which Deno cannot load from a
  `.ts` file) to `test/types.test.mts` with ESM imports, so `deno test
  --allow-read --unstable-detect-cjs test/` passes 153/153 (last verified
  2026-11-26) alongside `npm test` and `bun test`, which now pass 156/156;
  a Deno re-check at 156 is pending
  ([#82](https://github.com/sharkohark1234/redact-sensitive/issues/82)).
- Plain Deno import now works: `package.json` declares `"type": "commonjs"`,
  so Deno 2.9.8 detects the CommonJS module and
  `import { redact } from './src/index.js'` loads without the
  `--unstable-detect-cjs` flag
  ([#76](https://github.com/sharkohark1234/redact-sensitive/issues/76)).
- A host that merely contains "sentry" inside another label
  (`notsentry.example.com`) is no longer misclassified as a Sentry DSN:
  "sentry" must now be a whole dot-separated host label, so the key falls
  back to the email pattern instead
  ([#66](https://github.com/sharkohark1234/redact-sensitive/issues/66)).
- The API-key patterns now cover newer token formats: Stripe restricted keys
  (`rk_live_...`, `rk_test_...`), OpenAI service account keys (`sk-svcacct-...`),
  Slack `xoxe-...` tokens and AWS temporary session keys (`ASIA...`)
  ([#37](https://github.com/sharkohark1234/redact-sensitive/issues/37)).
- The email pattern no longer stalls on long digit-dash runs with no `@`
  (quadratic-time behaviour)
  ([#24](https://github.com/sharkohark1234/redact-sensitive/issues/24)).
- The `key = value` pattern now redacts base64 secret values in full: a
  `+` or `=` inside the value no longer leaves the tail unredacted
  ([#35](https://github.com/sharkohark1234/redact-sensitive/issues/35)).
- `redactObject` no longer drops symbol-keyed properties: enumerable
  symbol keys are carried over, and a value stored under a symbol whose
  description is a sensitive name (for example `Symbol('password')`) is
  redacted outright
  ([#23](https://github.com/sharkohark1234/redact-sensitive/issues/23)).

## [0.1.0]

### Added

- Initial release: redaction for emails, phone numbers, credit cards (Luhn),
  IBAN, GitHub/OpenAI/AWS/Slack API keys, JWTs, private-key blocks, SSNs,
  Indian PANs, IPv4 addresses, URL passwords, URL query-string secrets,
  `Authorization` headers, and `key = value` secrets.
- `redact()`, `redactObject()` and `findSensitive()`, with `only` / `except` /
  `labels` / `custom` options and TypeScript types.





