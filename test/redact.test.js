'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { redact, redactObject, findSensitive } = require('../src/index.js');

test('redacts an email address', () => {
  assert.equal(redact('Contact ana@example.com please'), 'Contact [EMAIL] please');
});

test('redacts a phone number', () => {
  assert.equal(redact('Call 555-123-4567'), 'Call [PHONE]');
});

test('redacts a valid credit card but keeps a random 16-digit number that fails Luhn', () => {
  assert.equal(redact('Card 4111 1111 1111 1111'), 'Card [CARD]');
  assert.equal(redact('Order 1234567890123456'), 'Order 1234567890123456');
});

test('redacts GitHub, OpenAI and AWS-style keys', () => {
  assert.equal(redact('token ghp_abcdefghij1234567890'), 'token [TOKEN]');
  assert.equal(redact('key sk-abcdefghij1234567890abcd'), 'key [API_KEY]');
  assert.equal(redact('key AKIAIOSFODNN7EXAMPLE'), 'key [AWS_KEY]');
});

test('redacts a password inside a URL only, keeping the rest', () => {
  assert.equal(
    redact('https://user:hunter2@example.com/x'),
    'https://user:[PASSWORD]@example.com/x'
  );
});

test('redacts nested values in objects and arrays', () => {
  assert.deepEqual(redactObject({ user: { email: 'a@b.com' }, tags: ['x@y.com'] }), {
    user: { email: '[EMAIL]' },
    tags: ['[EMAIL]'],
  });
});

test('findSensitive lists what was found', () => {
  const found = findSensitive('mail a@b.com, card 4111111111111111');
  assert.deepEqual(
    found.map((f) => f.type).sort(),
    ['creditCard', 'email']
  );
});

test('options.only limits redaction to one type', () => {
  assert.equal(redact('a@b.com 555-123-4567', { only: ['email'] }), '[EMAIL] 555-123-4567');
});

test('custom patterns are applied', () => {
  assert.equal(
    redact('order #12345', { custom: [{ pattern: '#\\d+', replacement: '[ORDER]' }] }),
    'order [ORDER]'
  );
});

test('leaves plain text untouched', () => {
  assert.equal(redact('Hello, world. No secrets here.'), 'Hello, world. No secrets here.');
});

test('redacts values stored under sensitive key names', () => {
  assert.deepEqual(
    redactObject({ password: 'hunter2', apiKey: 'abc123secret', user: 'ana' }),
    { password: '[PASSWORD]', apiKey: '[API_KEY]', user: 'ana' }
  );
});

test('sensitive key matching is case-insensitive and ignores separators', () => {
  assert.deepEqual(
    redactObject({ PASSWORD: 'x', Api_Key: 'y', 'access-key': 'z' }),
    { PASSWORD: '[PASSWORD]', Api_Key: '[API_KEY]', 'access-key': '[API_KEY]' }
  );
});

test('redacts sensitive keys nested in objects', () => {
  assert.deepEqual(
    redactObject({ config: { credentials: { token: 'tok123', host: 'example.com' } } }),
    { config: { credentials: { token: '[TOKEN]', host: 'example.com' } } }
  );
});

test('redacts sensitive keys inside arrays of objects', () => {
  assert.deepEqual(
    redactObject({ users: [{ name: 'ana', password: 'hunter2' }, { name: 'bob' }] }),
    { users: [{ name: 'ana', password: '[PASSWORD]' }, { name: 'bob' }] }
  );
});

test('non-sensitive keys keep their values (pattern redaction still applies)', () => {
  assert.deepEqual(
    redactObject({ user: 'ana', note: 'mail a@b.com', count: 3 }),
    { user: 'ana', note: 'mail [EMAIL]', count: 3 }
  );
});

test('redacts non-string values under sensitive keys', () => {
  assert.deepEqual(
    redactObject({ password: 12345, token: true, secret: null, apiKey: 0 }),
    { password: '[PASSWORD]', token: '[TOKEN]', secret: '[SECRET]', apiKey: '[API_KEY]' }
  );
});

test('options.sensitiveKeys extends the default sensitive key list', () => {
  assert.deepEqual(
    redactObject({ mySecretPhrase: 'shh', user: 'ana' }, { sensitiveKeys: ['mySecretPhrase'] }),
    { mySecretPhrase: '[REDACTED]', user: 'ana' }
  );
});

test('preserves a Date value inside an object while redacting a sibling email', () => {
  const created = new Date('2026-11-17T09:00:00.000Z');
  const out = redactObject({ created, email: 'a@b.com' });
  assert.ok(out.created instanceof Date);
  assert.equal(out.created.getTime(), created.getTime());
  assert.equal(out.email, '[EMAIL]');
});

test('returns a top-level Date unchanged', () => {
  const date = new Date('2026-11-17T09:00:00.000Z');
  assert.equal(redactObject(date), date);
});

test('preserves a RegExp value inside an object', () => {
  const pattern = /foo\d+/gi;
  const out = redactObject({ pattern });
  assert.equal(out.pattern, pattern);
  assert.equal(out.pattern.source, 'foo\\d+');
});

test('plain-object redaction still works after the non-plain fix', () => {
  assert.deepEqual(
    redactObject({ user: { email: 'a@b.com' }, tags: ['x@y.com'], when: new Date('2026-01-01T00:00:00.000Z') }),
    {
      user: { email: '[EMAIL]' },
      tags: ['[EMAIL]'],
      when: new Date('2026-01-01T00:00:00.000Z'),
    }
  );
});

test('redacts full and compressed IPv6 addresses', () => {
  assert.equal(redact('Connect to 2001:0db8:85a3:0000:0000:8a2e:0370:7334 now'), 'Connect to [IP] now');
  assert.equal(redact('Connect to 2001:db8::1 now'), 'Connect to [IP] now');
  assert.equal(redact('Connect to ::1 now'), 'Connect to [IP] now');
  assert.equal(redact('Route fe80:: and ::ffff:192.0.2.1.'), 'Route [IP] and [IP].');
});

test('leaves colon words that are not IPv6 addresses alone', () => {
  assert.equal(redact('Use std::vector and Foo::Bar'), 'Use std::vector and Foo::Bar');
  assert.equal(redact('At 12:30:45 see note a:b:c'), 'At 12:30:45 see note a:b:c');
  assert.equal(redact('Bad 1:2:3:4:5:6:7:8:9 and 1::2::3'), 'Bad 1:2:3:4:5:6:7:8:9 and 1::2::3');
  assert.equal(redact('Not an address: ::'), 'Not an address: ::');
  assert.equal(redact('Price 12.50:: total'), 'Price 12.50:: total');
});

test('IPv4 redaction is unchanged', () => {
  assert.equal(redact('From 203.0.113.42 and 999.1.1.1'), 'From [IP] and 999.1.1.1');
});
