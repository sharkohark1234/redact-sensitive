'use strict';

// --- Issue #9: TypeScript usage ---
// The types in src/index.d.ts must stay in step with the runtime exports.
// These tests import the types (import type) and exercise the matching
// runtime values, so a drift between src/index.js and src/index.d.ts fails
// here. Run with `npm test` — Node strips the types natively, no build step.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { redact, redactObject, findSensitive, PATTERNS, SENSITIVE_KEYS } = require('../src/index.js');
import type { RedactOptions, SensitiveMatch, RedactPattern } from '../src/index.js';

test('RedactOptions type: typed options redact as documented in the README', () => {
  const options: RedactOptions = { only: ['email'] };
  const safe: string = redact('Contact ana@example.com', options);
  assert.equal(safe, 'Contact [EMAIL]');
});

test('redactObject keeps the input type, so the result has the same shape', () => {
  const payload = redactObject({ user: 'ana@example.com', tags: ['x@y.com'] });
  assert.deepEqual(payload, { user: '[EMAIL]', tags: ['[EMAIL]'] });
  // The generic preserves the object type: assigning the result back to a
  // variable of the input type must type-check.
  const sameShape: { user: string; tags: string[] } = payload;
  assert.equal(sameShape.user, '[EMAIL]');
});

test('SensitiveMatch type: findSensitive returns typed matches sorted by position', () => {
  const found: SensitiveMatch[] = findSensitive('mail a@b.com');
  assert.deepEqual(found, [{ type: 'email', value: 'a@b.com', index: 5 }]);
});

test('RedactPattern type: PATTERNS entries have name, label and regex', () => {
  const patterns: RedactPattern[] = PATTERNS;
  assert.ok(patterns.length > 0);
  for (const pattern of patterns) {
    assert.equal(typeof pattern.name, 'string');
    assert.equal(typeof pattern.label, 'string');
    assert.ok(pattern.regex instanceof RegExp);
  }
  assert.ok(patterns.some((p) => p.name === 'email'));
});

test('SENSITIVE_KEYS type: default sensitive keys map to their labels', () => {
  const keys: Map<string, string> = SENSITIVE_KEYS;
  assert.equal(keys.get('password'), '[PASSWORD]');
  assert.equal(keys.get('apikey'), '[API_KEY]');
});
