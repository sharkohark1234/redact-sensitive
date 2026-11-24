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

test('redacts a valid IBAN but keeps an IBAN-shaped string that fails the checksum', () => {
  // Public example IBANs from ISO 13616 / bank documentation, not real accounts.
  assert.equal(redact('Pay to DE89 3704 0044 0532 0130 00 today'), 'Pay to [IBAN] today');
  assert.equal(redact('IBAN: GB82WEST12345698765432'), 'IBAN: [IBAN]');
  assert.equal(redact('Product code AB12 CDEF GHIJ KLMN'), 'Product code AB12 CDEF GHIJ KLMN');
});

test('IBAN match stops at the country length, so a following word is not pulled in', () => {
  assert.equal(redact('BE68 5390 0754 7034 CODE'), '[IBAN] CODE');
  assert.equal(redact('NO93 8601 1117 947 ok'), '[IBAN] ok');
});

test('IBAN with an unknown country code is not reported, even with a valid checksum', () => {
  // XX is not an IBAN country; check digits 46 make the mod-97 sum valid.
  assert.deepEqual(findSensitive('XX46370400440532013000'), []);
});

test('redacts GitHub, OpenAI and AWS-style keys', () => {
  assert.equal(redact('token ghp_abcdefghij1234567890'), 'token [TOKEN]');
  assert.equal(redact('key sk-abcdefghij1234567890abcd'), 'key [API_KEY]');
  assert.equal(redact('key AKIAIOSFODNN7EXAMPLE'), 'key [AWS_KEY]');
});

test('redacts Stripe secret keys but not publishable keys', () => {
  // Built at runtime so no key-shaped literal is committed (secret scanners flag those).
  const body = 'a'.repeat(24);
  assert.equal(redact(`key sk_live_${body}`), 'key [API_KEY]');
  assert.equal(redact(`key sk_test_${body}`), 'key [API_KEY]');
  assert.equal(redact(`key pk_live_${body}`), `key pk_live_${body}`);
  assert.equal(redact('key sk_live_short'), 'key sk_live_short');
});

test('redacts ENCRYPTED PRIVATE KEY blocks', () => {
  assert.equal(
    redact('-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIBvTCCAUY=\n-----END ENCRYPTED PRIVATE KEY-----'),
    '[PRIVATE_KEY]'
  );
});

test('redacts a truncated private key block that has no END line', () => {
  assert.equal(
    redact('key dump:\n-----BEGIN PRIVATE KEY-----\nMIIBvTCCAUYgAwIBAgI='),
    'key dump:\n[PRIVATE_KEY]'
  );
  assert.equal(
    redact('-----BEGIN RSA PRIVATE KEY-----\nMIIBvTCCAUYgAwIBAgIMIIBvTCCAUYgAwIBAgI\nMIIBvTCCAUYgAwIBAgIMIIBvTCCAUYgAwIBAgI'),
    '[PRIVATE_KEY]'
  );
});

test('a truncated private key block does not swallow the text after it', () => {
  assert.equal(
    redact('-----BEGIN PRIVATE KEY-----\nMIIBvTCCAUYgAwIBAgI=\nnext log line'),
    '[PRIVATE_KEY]\nnext log line'
  );
});

test('two complete private key blocks are redacted separately', () => {
  assert.equal(
    redact('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\nkeep\n-----BEGIN EC PRIVATE KEY-----\nBBBB\n-----END EC PRIVATE KEY-----'),
    '[PRIVATE_KEY]\nkeep\n[PRIVATE_KEY]'
  );

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

test('redacts an Indian PAN number', () => {
  assert.equal(redact('PAN ABCDE1234F on file'), 'PAN [PAN] on file');
});

test('keeps text that only looks like an Indian PAN number', () => {
  assert.equal(redact('code ABCDE1234'), 'code ABCDE1234');
  assert.equal(redact('ref ABCDE1234FG'), 'ref ABCDE1234FG');
  assert.equal(redact('pan abcde1234f'), 'pan abcde1234f');
});

test('findSensitive lists what was found', () => {
  const found = findSensitive('mail a@b.com, card 4111111111111111');
  assert.deepEqual(
    found.map((f) => f.type).sort(),
    ['creditCard', 'email']
  );
});

// --- Issue #25: findSensitive returns matches in text order and honours options ---

test('findSensitive returns matches in text order with their index', () => {
  const found = findSensitive('card 4111111111111111 then mail a@b.com then phone 555-123-4567');
  assert.deepEqual(found, [
    { type: 'creditCard', value: '4111111111111111', index: 5 },
    { type: 'email', value: 'a@b.com', index: 32 },
    { type: 'phone', value: '555-123-4567', index: 51 },
  ]);
});

test('findSensitive honours options.only', () => {
  const found = findSensitive('mail a@b.com, card 4111111111111111', { only: ['email'] });
  assert.deepEqual(found, [{ type: 'email', value: 'a@b.com', index: 5 }]);
});

test('findSensitive honours options.except', () => {
  const found = findSensitive('mail a@b.com, card 4111111111111111', { except: ['email'] });
  assert.deepEqual(found, [{ type: 'creditCard', value: '4111111111111111', index: 19 }]);
});

test('findSensitive reports custom patterns as type custom', () => {
  const found = findSensitive('order #12345 and a@b.com', { custom: [{ pattern: '#\\d+' }] });
  assert.deepEqual(found, [
    { type: 'custom', value: '#12345', index: 6 },
    { type: 'email', value: 'a@b.com', index: 17 },
  ]);
});

test('findSensitive rejects unknown names in only', () => {
  assert.throws(() => findSensitive('a@b.com', { only: ['emial'] }), RangeError);
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

// --- Issue #13: secrets in URL query strings ---

test('redacts only the value of sensitive query params, keeping other params', () => {
  assert.equal(
    redact('GET https://example.com/callback?token=abc123&user=ana&page=2'),
    'GET https://example.com/callback?token=[TOKEN]&user=ana&page=2'
  );
  assert.equal(
    redact('https://example.com/x?access_token=zzz&auth=yyy&lang=en'),
    'https://example.com/x?access_token=[TOKEN]&auth=[TOKEN]&lang=en'
  );
});

test('query param labels follow the param name', () => {
  assert.equal(redact('?api_key=abcdef0123'), '?api_key=[API_KEY]');
  assert.equal(redact('?client_secret=s3cr3tvalue'), '?client_secret=[SECRET]');
  assert.equal(redact('?password=hunter2'), '?password=[PASSWORD]');
  assert.equal(redact('?refresh_token=tok123'), '?refresh_token=[TOKEN]');
  assert.equal(redact('?sessionid=abc123'), '?sessionid=[TOKEN]');
  assert.equal(redact('?apiKey=abcdef0123'), '?apiKey=[API_KEY]');
});

test('query secret redaction is case-insensitive and stops at a fragment', () => {
  assert.equal(redact('?TOKEN=abc123'), '?TOKEN=[TOKEN]');
  assert.equal(redact('?token=abc123#section'), '?token=[TOKEN]#section');
});

test('query secret redaction works inside longer log lines and object values', () => {
  assert.equal(
    redact('200 GET /cb?token=abc123 HTTP/1.1'),
    '200 GET /cb?token=[TOKEN] HTTP/1.1'
  );
  assert.deepEqual(
    redactObject({ url: 'https://example.com/cb?token=abc123&user=ana' }),
    { url: 'https://example.com/cb?token=[TOKEN]&user=ana' }
  );
});

test('query secret redaction respects only / except / keepLabels', () => {
  assert.equal(redact('?token=abc123', { only: ['email'] }), '?token=abc123');
  assert.equal(redact('?token=abc123', { except: ['urlQuerySecret'] }), '?token=abc123');
  assert.equal(redact('?token=abc123', { keepLabels: false, replacement: '***' }), '?token=***');
  assert.equal(redact('?token=abc123', { labels: { urlQuerySecret: '[Q]' } }), '?token=[Q]');
});

test('query secret false positives stay untouched', () => {
  assert.equal(redact('?user=ana&page=2'), '?user=ana&page=2');
  // The param name must match exactly: longer names are not secrets.
  assert.equal(redact('?mytoken=abc123'), '?mytoken=abc123');
  assert.equal(redact('?tokenized=abc123'), '?tokenized=abc123');
  // An empty value has nothing to leak.
  assert.equal(redact('?token='), '?token=');
  // 'token' as a bare word in prose is not a query param.
  assert.equal(redact('your token is abc123'), 'your token is abc123');
});

// --- Issue #6: per-type custom replacement labels ---

test('options.labels overrides one pattern label at a time', () => {
  assert.equal(
    redact('a@b.com 555-123-4567', { labels: { email: '[E-MAIL]', phone: '[TEL]' } }),
    '[E-MAIL] [TEL]'
  );
  // A label for one type leaves every other type on its default label.
  assert.equal(redact('a@b.com', { labels: { phone: '[TEL]' } }), '[EMAIL]');
  assert.equal(redact('Call 555-123-4567', { labels: { email: '[E-MAIL]' } }), 'Call [PHONE]');
});

test('keepLabels: false wins over per-type labels', () => {
  assert.equal(
    redact('a@b.com', { labels: { email: '[E-MAIL]' }, keepLabels: false, replacement: '***' }),
    '***'
  );
});

test('options.labels works through redactObject, including sensitive keys', () => {
  assert.deepEqual(
    redactObject({ note: 'mail a@b.com' }, { labels: { email: '[E-MAIL]' } }),
    { note: 'mail [E-MAIL]' }
  );
  assert.deepEqual(
    redactObject({ password: 'hunter2' }, { labels: { password: '[PWD]' } }),
    { password: '[PWD]' }
  );
});

test('options.labels applies to urlPassword and genericApiKey too', () => {
  assert.equal(
    redact('https://user:hunter2@example.com/x', { labels: { urlPassword: '[PW]' } }),
    'https://user:[PW]@example.com/x'
  );
  assert.equal(
    redact('https://user:hunter2@example.com/x', { keepLabels: false, replacement: '***' }),
    'https://user:***@example.com/x'
  );
  assert.equal(
    redact('api_key = abcdefgh12345678', { labels: { genericApiKey: '[KEY]' } }),
    'api_key = [KEY]'
  );
});

// The README and landing page show this exact example, so pin it: a short
// placeholder such as `sk-...` would not be redacted at all, but a
// `key = value` secret is.
test('README example: card and key = value secret redact as documented', () => {
  assert.equal(
    redact('Card 4111 1111 1111 1111, api_key = abc123secret'),
    'Card [CARD], api_key = [API_KEY]'
  );
});

// --- Authorization header values in log text ---

test('redacts Bearer and Basic credentials, keeping header name and scheme', () => {
  assert.equal(redact('Authorization: Bearer abc123opaque'), 'Authorization: Bearer [TOKEN]');
  assert.equal(redact('Authorization: Basic dXNlcjpwYXNz'), 'Authorization: Basic [CREDENTIALS]');
});

test('auth header redaction is case-insensitive and covers Proxy-Authorization', () => {
  assert.equal(redact('authorization: Bearer xyz'), 'authorization: Bearer [TOKEN]');
  assert.equal(redact('Proxy-Authorization: Basic dXNlcjpwYXNz'), 'Proxy-Authorization: Basic [CREDENTIALS]');
});

test('auth header redaction works inside longer log lines', () => {
  assert.equal(
    redact('request headers: Authorization: Bearer abc123, Content-Type: text/plain'),
    'request headers: Authorization: Bearer [TOKEN], Content-Type: text/plain'
  );
});

test('auth header redaction respects only / except / keepLabels', () => {
  assert.equal(redact('Authorization: Bearer abc', { only: ['email'] }), 'Authorization: Bearer abc');
  assert.equal(redact('Authorization: Bearer abc', { except: ['authHeader'] }), 'Authorization: Bearer abc');
  assert.equal(
    redact('Authorization: Bearer abc', { keepLabels: false, replacement: '***' }),
    'Authorization: Bearer ***'
  );
});

test('other auth schemes are left alone', () => {
  // Deliberate choice: only Bearer (reusable opaque token) and Basic
  // (base64 username:password) are redacted. Negotiate, Digest and friends
  // carry session-bound challenge responses, not static credentials, so
  // they are not treated as secrets here.
  assert.equal(redact('Authorization: Negotiate YIIabc123'), 'Authorization: Negotiate YIIabc123');
  assert.equal(redact('Authorization: Digest username="ana"'), 'Authorization: Digest username="ana"');
  // A scheme with no credential has nothing to leak.
  assert.equal(redact('Authorization: Bearer'), 'Authorization: Bearer');
});

// --- Issue #56: session cookie values in Cookie / Set-Cookie headers ---

test('redacts session cookie values, keeping harmless cookies', () => {
  assert.equal(
    redact('Cookie: session=abc123; theme=dark'),
    'Cookie: session=[TOKEN]; theme=dark'
  );
  assert.equal(
    redact('Cookie: theme=dark; sid=abc123; lang=en'),
    'Cookie: theme=dark; sid=[TOKEN]; lang=en'
  );
  assert.equal(
    redact('Cookie: token=abc123; prefs=compact'),
    'Cookie: token=[TOKEN]; prefs=compact'
  );
});

test('redacts Set-Cookie session values, keeping attributes readable', () => {
  assert.equal(
    redact('Set-Cookie: sid=abc123; HttpOnly; Path=/'),
    'Set-Cookie: sid=[TOKEN]; HttpOnly; Path=/'
  );
  assert.equal(
    redact('Set-Cookie: session=abc123; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; SameSite=Lax; Max-Age=3600'),
    'Set-Cookie: session=[TOKEN]; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; SameSite=Lax; Max-Age=3600'
  );
});

test('session cookie names match like query params: separators and case ignored', () => {
  assert.equal(redact('Cookie: session_id=abc123'), 'Cookie: session_id=[TOKEN]');
  assert.equal(redact('Cookie: session-id=abc123'), 'Cookie: session-id=[TOKEN]');
  assert.equal(redact('Cookie: sessionId=abc123'), 'Cookie: sessionId=[TOKEN]');
  assert.equal(redact('Cookie: SESSIONID=abc123'), 'Cookie: SESSIONID=[TOKEN]');
  assert.equal(redact('Cookie: SID=abc123'), 'Cookie: SID=[TOKEN]');
  assert.equal(redact('Cookie: auth=abc123'), 'Cookie: auth=[TOKEN]');
  assert.equal(redact('Cookie: access_token=abc123'), 'Cookie: access_token=[TOKEN]');
});

test('session cookie header names are case-insensitive', () => {
  assert.equal(redact('cookie: session=abc123'), 'cookie: session=[TOKEN]');
  assert.equal(redact('COOKIE: session=abc123'), 'COOKIE: session=[TOKEN]');
  assert.equal(redact('set-cookie: sid=abc123; HttpOnly'), 'set-cookie: sid=[TOKEN]; HttpOnly');
});

test('session cookie false positives stay untouched', () => {
  // The cookie name must match exactly: longer names are not sessions.
  assert.equal(redact('Cookie: mysession=abc123'), 'Cookie: mysession=abc123');
  assert.equal(redact('Cookie: sessionid2=abc123'), 'Cookie: sessionid2=abc123');
  assert.equal(redact('Cookie: tokenized=abc123'), 'Cookie: tokenized=abc123');
  assert.equal(redact('Cookie: authuser=ana'), 'Cookie: authuser=ana');
  // A session word outside a Cookie header is not a cookie.
  assert.equal(redact('your session is abc123'), 'your session is abc123');
  // An empty value has nothing to leak.
  assert.equal(redact('Cookie: session=; theme=dark'), 'Cookie: session=; theme=dark');
  // A cookie with no '=' at all is a flag, not a value.
  assert.equal(redact('Set-Cookie: theme=dark; HttpOnly'), 'Set-Cookie: theme=dark; HttpOnly');
});

test('session cookie redaction handles quoted values and longer log lines', () => {  assert.equal(
    redact('Cookie: session="abc123"; theme=dark'),
    'Cookie: session="[TOKEN]"; theme=dark'
  );
  assert.equal(
    redact('request headers: Cookie: session=abc123; theme=dark, Content-Type: text/plain'),
    'request headers: Cookie: session=[TOKEN]; theme=dark, Content-Type: text/plain'
  );
  assert.deepEqual(
    redactObject({ headers: 'Cookie: session=abc123; theme=dark' }),
    { headers: 'Cookie: session=[TOKEN]; theme=dark' }
  );
  // Two header lines in one log are both redacted.
  assert.equal(
    redact('Cookie: session=abc123\nSet-Cookie: sid=def456; HttpOnly'),
    'Cookie: session=[TOKEN]\nSet-Cookie: sid=[TOKEN]; HttpOnly'
  );
});

test('unquoted session cookie value does not swallow a closing quote', () => {
  // '"' is not a cookie-octet (RFC 6265), so an unquoted value ends at
  // the closing quote of surrounding log syntax (e.g. a JSON string)
  // and that syntax is kept untouched.
  assert.equal(
    redact('{"headers": "Cookie: session=abc123"}'),
    '{"headers": "Cookie: session=[TOKEN]"}'
  );
  assert.equal(
    redact('{"headers": "Set-Cookie: sid=abc123; HttpOnly"}'),
    '{"headers": "Set-Cookie: sid=[TOKEN]; HttpOnly"}'
  );
});

test('session cookie redaction respects only / except / keepLabels and is reported by findSensitive', () => {
  assert.equal(redact('Cookie: session=abc123', { only: ['email'] }), 'Cookie: session=abc123');
  assert.equal(redact('Cookie: session=abc123', { except: ['sessionCookie'] }), 'Cookie: session=abc123');
  assert.equal(
    redact('Cookie: session=abc123', { keepLabels: false, replacement: '***' }),
    'Cookie: session=***'
  );
  assert.equal(
    redact('Cookie: session=abc123', { labels: { sessionCookie: '[S]' } }),
    'Cookie: session=[S]'
  );
  const found = findSensitive('Cookie: session=abc123; theme=dark');
  assert.ok(found.some((f) => f.type === 'sessionCookie'));
});

test('findSensitive reports the new pattern types', () => {
  const found = findSensitive('?token=abc123 and Authorization: Bearer xyz');
  assert.deepEqual(
    found.map((f) => f.type).sort(),
    ['authHeader', 'urlQuerySecret']
  );
});

// Unknown option names must not silently disable or change redaction.
for (const option of ['only', 'except', 'labels']) {
  test(`rejects unknown names in ${option}`, () => {
    const options = { [option]: option === 'labels' ? { emial: '[MAIL]' } : ['emial'] };
    for (const input of ['a@example.com', '', null, 42]) {
      assert.throws(() => redact(input, options), (error) => {
        assert.ok(error instanceof RangeError);
        assert.match(error.message, new RegExp(option));
        assert.match(error.message, /emial/);
        assert.match(error.message, /email/);
        return true;
      });
    }
    for (const input of [{}, [], { password: 'synthetic' }]) {
      assert.throws(() => redactObject(input, options), RangeError);
    }
  });
}

test('accepts all current pattern names and sensitive-key labels', () => {
  const { PATTERNS, SENSITIVE_KEYS } = require('../src');
  const names = PATTERNS.map((pattern) => pattern.name);
  assert.equal(redact('a@example.com', { only: names }), '[EMAIL]');
  assert.equal(redact('a@example.com', { except: names }), 'a@example.com');
  assert.equal(redact('a@example.com', { only: [] }), 'a@example.com');
  const labels = Object.fromEntries([...names, ...SENSITIVE_KEYS.keys()].map((name) => [name, '[CUSTOM]']));
  assert.deepEqual(redactObject({ password: 'synthetic', note: 'a@example.com' }, { labels }), {
    password: '[CUSTOM]', note: '[CUSTOM]',
  });
});

test('sensitive key names are not accepted as pattern filters', () => {
  assert.throws(() => redact('text', { only: ['password'] }), RangeError);
  assert.throws(() => redact('text', { except: ['password'] }), RangeError);
});

test('every PATTERNS entry matches the exported TypeScript shape', () => {
  const { PATTERNS } = require('../src');
  assert.ok(Array.isArray(PATTERNS));
  assert.ok(PATTERNS.length > 0);
  for (const pattern of PATTERNS) {
    assert.equal(typeof pattern.name, 'string');
    assert.equal(typeof pattern.label, 'string');
    assert.ok(pattern.regex instanceof RegExp);
    if (pattern.replacement !== undefined) {
      assert.ok(typeof pattern.replacement === 'string' || typeof pattern.replacement === 'function');
    }
    if (pattern.labelFor !== undefined) assert.equal(typeof pattern.labelFor, 'function');
    if (pattern.validate !== undefined) assert.equal(typeof pattern.validate, 'function');
  }
  // Spot-check the specialised entries the type has to cover.
  const byName = Object.fromEntries(PATTERNS.map((p) => [p.name, p]));
  assert.equal(typeof byName.urlPassword.replacement, 'string');
  assert.equal(typeof byName.connectionString.replacement, 'function');
  assert.equal(typeof byName.genericApiKey.replacement, 'function');
  assert.equal(typeof byName.urlQuerySecret.labelFor, 'function');
  assert.equal(typeof byName.authHeader.labelFor, 'function');
  assert.equal(typeof byName.iban.validate, 'function');
});

// --- Issue #22: redactObject crashes on circular references and very deep nesting ---

test('redactObject replaces a self-reference with [Circular] instead of throwing', () => {
  const c = { name: 'ana' };
  c.self = c;
  assert.deepEqual(redactObject(c), { name: 'ana', self: '[Circular]' });
});

test('redactObject replaces a mutual two-object cycle with [Circular]', () => {
  const a = { name: 'ana' };
  const b = { name: 'bob', back: a };
  a.other = b;
  const out = redactObject(a);
  assert.equal(out.name, 'ana');
  assert.equal(out.other.name, 'bob');
  assert.equal(out.other.back, '[Circular]');
});

test('redactObject replaces a self-referencing array with [Circular]', () => {
  const arr = ['a@b.com'];
  arr.push(arr);
  assert.deepEqual(redactObject(arr), ['[EMAIL]', '[Circular]']);
});

test('redactObject does not mistake a shared non-circular object for a cycle', () => {
  const shared = { email: 'a@b.com' };
  assert.deepEqual(redactObject({ first: shared, second: shared }), {
    first: { email: '[EMAIL]' },
    second: { email: '[EMAIL]' },
  });
});

test('redactObject does not throw on a 5,000-deep object and caps it with a placeholder', () => {
  let deep = { leaf: 'a@b.com' };
  for (let i = 0; i < 5000; i++) deep = { next: deep };
  let out;
  assert.doesNotThrow(() => {
    out = redactObject(deep);
  });
  // Walk down until the depth cap: the value there is the placeholder.
  let cur = out;
  let steps = 0;
  while (typeof cur === 'object' && cur !== null) {
    cur = cur.next;
    steps++;
  }
  assert.equal(cur, '[DEPTH_LIMIT]');
  assert.ok(steps <= 101, `depth cap reached after ${steps} levels`);
});

test('redactObject honours options.maxDepth', () => {
  const value = { a: { b: { c: { d: 'x' } } } };
  assert.deepEqual(redactObject(value, { maxDepth: 2 }), {
    a: { b: { c: '[DEPTH_LIMIT]' } },
  });
});

test('redaction still works inside nested objects and arrays after the circular/depth fix', () => {
  assert.deepEqual(
    redactObject({
      user: { email: 'a@b.com', password: 'hunter2' },
      tags: ['x@y.com', { note: 'mail a@b.com' }],
    }),
    {
      user: { email: '[EMAIL]', password: '[PASSWORD]' },
      tags: ['[EMAIL]', { note: 'mail [EMAIL]' }],
    }
  );
});

// --- Issue #24: email regex was quadratic on long digit-dash runs ---

test('email pattern stays fast on a long digit-dash run with no @', () => {
  const input = '1-'.repeat(40000); // 80k chars
  const start = process.hrtime.bigint();
  const out = redact(input, { only: ['email'] });
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  assert.equal(out, input);
  // Was several seconds before the fix; generous bound to avoid CI flakiness.
  assert.ok(ms < 1000, `redaction took ${ms.toFixed(0)} ms`);
});

test('a real email at the end of a long digit-dash run is still redacted', () => {
  assert.equal(
    redact('1-'.repeat(1000) + 'ana@example.com', { only: ['email'] }),
    '[EMAIL]'
  );
  assert.equal(redact('id 1-2-3 mail ana-b@example.com', { only: ['email'] }), 'id 1-2-3 mail [EMAIL]');
});

// --- Issue #20: AWS-style compound secret key names ---

test('genericApiKey redacts aws_secret_access_key and secret_access_key values', () => {
  const value = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
  assert.equal(redact(`aws_secret_access_key = ${value}`), 'aws_secret_access_key = [API_KEY]');
  assert.equal(redact(`secret_access_key = ${value}`), 'secret_access_key = [API_KEY]');
  assert.equal(redact(`AWS_SECRET_ACCESS_KEY=${value}`), 'AWS_SECRET_ACCESS_KEY=[API_KEY]');
  assert.equal(redact(`aws-secret-access-key: ${value}`), 'aws-secret-access-key: [API_KEY]');
  assert.equal(redact(`SecretAccessKey = "${value}"`), 'SecretAccessKey = "[API_KEY]"');
});

test('plain secret = ... still works and unrelated compound names are untouched', () => {
  assert.equal(redact('secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'), 'secret = [API_KEY]');
  assert.equal(redact('secret_access_key_id = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'), 'secret_access_key_id = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
});

// --- Issue #37: newer Stripe / OpenAI / Slack / AWS token formats ---

// Bodies are built at runtime so no key-shaped literal is committed (secret
// scanners flag those). They are deliberately obvious placeholders.
const body24 = () => 'a'.repeat(24);
const body16 = () => 'ab'.repeat(8);
const awsBody16 = () => 'A1'.repeat(8);

test('redacts Stripe restricted keys (rk_live_ / rk_test_) as API keys', () => {
  assert.equal(redact(`key rk_live_${body24()}`), 'key [API_KEY]');
  assert.equal(redact(`key rk_test_${body24()}`), 'key [API_KEY]');
  const found = findSensitive(`key rk_live_${body24()}`);
  assert.ok(found.some((f) => f.type === 'stripeKey'));
});

test('redacts OpenAI service account keys (sk-svcacct-) as API keys', () => {
  assert.equal(redact(`key sk-svcacct-${body24()}`), 'key [API_KEY]');
  const found = findSensitive(`key sk-svcacct-${body24()}`);
  assert.ok(found.some((f) => f.type === 'openaiKey'));
});

// --- Issue #74: Anthropic Claude API keys ---

test('redacts Anthropic Claude API keys as API keys', () => {
  const body = 'A'.repeat(93) + 'AA';
  const api03 = `sk-ant-api03-${body}`;
  const admin01 = `sk-ant-admin01-${body}`;
  assert.equal(redact(`key ${api03}`), 'key [API_KEY]');
  assert.equal(redact(`key ${admin01}`), 'key [API_KEY]');
  assert.deepEqual(findSensitive(`key ${api03}`, { only: ['anthropicApiKey'] }), [
    { type: 'anthropicApiKey', value: api03, index: 4 },
  ]);
});

test('Anthropic API key near misses stay untouched', () => {
  const body = 'A'.repeat(93) + 'AA';
  const inputs = [
    'sk-ant-api03-short',
    `sk-ant-api03-${'A'.repeat(10)}`,
    `sk-ant-api03-${'A'.repeat(92)}AA`,
    `sk-ant-api03-${'A'.repeat(94)}AA`,
    `sk-ant-api03-${'A'.repeat(93)}AB`,
    `sk-ant-api03-${'A'.repeat(93)}A!`,
    `sk-ant-admin01-${'A'.repeat(92)}AA`,
    `sk-ant-api03-${body}extra`,
    'plain text with sk-ant-api03- inside',
  ];
  for (const input of inputs) {
    assert.equal(redact(input), input);
    assert.deepEqual(findSensitive(input, { only: ['anthropicApiKey'] }), []);
  }
});

test('Anthropic API key embedded after hyphen or underscore stays untouched', () => {
  const body = 'A'.repeat(93) + 'AA';
  const api03 = `sk-ant-api03-${body}`;
  const hyphenPrefixed = `prefix-${api03}`;
  const underscorePrefixed = `prefix_${api03}`;
  assert.equal(redact(hyphenPrefixed), hyphenPrefixed);
  assert.equal(redact(underscorePrefixed), underscorePrefixed);
  assert.deepEqual(findSensitive(hyphenPrefixed, { only: ['anthropicApiKey'] }), []);
  assert.deepEqual(findSensitive(underscorePrefixed, { only: ['anthropicApiKey'] }), []);
});

test('redacts Slack xoxe- tokens as tokens', () => {
  assert.equal(redact(`value xoxe-${body16()}`), 'value [TOKEN]');
  const found = findSensitive(`value xoxe-${body16()}`);
  assert.ok(found.some((f) => f.type === 'slackToken'));
});

test('redacts AWS temporary session keys (ASIA...) as AWS keys', () => {
  assert.equal(redact(`key ASIA${awsBody16()}`), 'key [AWS_KEY]');
  const found = findSensitive(`key ASIA${awsBody16()}`);
  assert.ok(found.some((f) => f.type === 'awsAccessKey'));
});

test('new formats keep existing controls: publishable keys stay, old formats still redact', () => {
  // Stripe publishable keys are not secrets and must stay visible.
  assert.equal(redact(`key pk_live_${body24()}`), `key pk_live_${body24()}`);
  // Legacy formats keep working.
  assert.equal(redact(`key sk_live_${body24()}`), 'key [API_KEY]');
  assert.equal(redact('token ghp_abcdefghij1234567890'), 'token [TOKEN]');
  assert.equal(redact('key AKIAIOSFODNN7EXAMPLE'), 'key [AWS_KEY]');
  // Near misses of the new prefixes are not redacted.
  assert.equal(redact('key rk_live_short'), 'key rk_live_short');
  assert.equal(redact('key pk_test_' + body24()), 'key pk_test_' + body24());
  assert.equal(redact('value xoxe-short'), 'value xoxe-short');
  // Existing OpenAI project keys still work beside svcacct.
  assert.equal(redact(`key sk-proj-${body24()}`), 'key [API_KEY]');
});

// --- Issue #39: over-long AKIA/ASIA access key ids ---

// Deliberately obvious placeholders built at runtime (no key-shaped literals).
const awsBody17 = () => 'A1'.repeat(8) + 'Z'; // 17 chars -> 21 total
const awsBody24 = () => 'A1'.repeat(12);      // 24 chars -> 28 total

test('redacts over-long AKIA/ASIA access key ids as AWS keys', () => {
  for (const prefix of ['AKIA', 'ASIA']) {
    for (const body of [awsBody17(), awsBody24()]) {
      assert.equal(redact(`key ${prefix}${body}`), 'key [AWS_KEY]');
      const found = findSensitive(`key ${prefix}${body}`);
      assert.ok(found.some((f) => f.type === 'awsAccessKey'));
    }
  }
});

test('over-long AWS keys keep existing length boundaries', () => {
  // The standard 20-char key still redacts.
  assert.equal(redact(`key AKIA${awsBody16()}`), 'key [AWS_KEY]');
  // Too-short values are left alone.
  assert.equal(redact(`key AKIA${'A1'.repeat(4)}`), `key AKIA${'A1'.repeat(4)}`);
  // Word boundary still holds: a trailing lowercase letter breaks the match.
  const nonKey = `AKIA${awsBody16()}abc`;
  assert.equal(redact(`key ${nonKey}`), `key ${nonKey}`);
});

// --- Issue #35: genericApiKey left base64 tails (+ / =) unredacted ---

test('genericApiKey redacts base64 values containing + in full', () => {
  assert.equal(
    redact('aws_secret_access_key = abcDEF123+GhIjKlMnOpQrStUvWx'),
    'aws_secret_access_key = [API_KEY]'
  );
  assert.equal(redact('secret = abcDEF123+GhIjKlMnOpQrStUvWx'), 'secret = [API_KEY]');
  assert.equal(redact('token = abcDEF123+GhIjKlMnOpQrStUvWx'), 'token = [API_KEY]');
});

test('genericApiKey redacts base64 padding at the end of a value', () => {
  assert.equal(
    redact('aws_secret_access_key = abcDEF1234567890Yz=='),
    'aws_secret_access_key = [API_KEY]'
  );
  // A closing quote is not swallowed when the value ends in padding.
  assert.equal(redact('secret = "abcDEF123+GhIjKlMnOpQrStUvWx=="'), 'secret = "[API_KEY]"');
});

test('genericApiKey redacts a value made of + / = plus alphanumerics', () => {
  assert.equal(redact('token = ++==abcDEF123456'), 'token = [API_KEY]');
  // The 8-character minimum still applies to short values.
  assert.equal(redact('secret = abc=='), 'secret = abc==');
});

// --- Issue #23: redactObject silently dropped symbol-keyed properties ---

test('redactObject preserves symbol-keyed properties and redacts their values', () => {
  const sym = Symbol('note');
  const out = redactObject({ user: 'ana', [sym]: 'contact ana@example.com' });
  assert.equal(Object.getOwnPropertySymbols(out).length, 1);
  assert.equal(out[sym], 'contact [EMAIL]');
});

test('redactObject redacts values under symbol keys with sensitive descriptions', () => {
  const symPassword = Symbol('password');
  assert.equal(redactObject({ [symPassword]: 'hunter2' })[symPassword], '[PASSWORD]');
  const symApiKey = Symbol('api_key');
  assert.equal(redactObject({ [symApiKey]: 'hunter2' })[symApiKey], '[API_KEY]');
  // A symbol with no description is preserved and content-redacted.
  const symAnon = Symbol();
  assert.equal(redactObject({ [symAnon]: 'ana@example.com' })[symAnon], '[EMAIL]');
});

test('redactObject recurses into objects stored under symbol keys', () => {
  const sym = Symbol('meta');
  const out = redactObject({ [sym]: { email: 'a@b.com' } });
  assert.deepEqual(out[sym], { email: '[EMAIL]' });
});

test('redactObject treats non-enumerable keys the same for symbols and strings', () => {
  const sym = Symbol('hidden');
  const input = { visible: 'ana@example.com' };
  Object.defineProperty(input, sym, { value: 'hunter2', enumerable: false });
  Object.defineProperty(input, 'hiddenString', { value: 'hunter2', enumerable: false });
  const out = redactObject(input);
  assert.equal(Object.getOwnPropertySymbols(out).length, 0);
  assert.equal('hiddenString' in out, false);
  assert.equal(out.visible, '[EMAIL]');
});

test('redactObject handles a symbol-keyed self-reference without throwing', () => {
  const sym = Symbol('self');
  const input = { name: 'ana' };
  input[sym] = input;
  const out = redactObject(input);
  assert.equal(out[sym], '[Circular]');
});

// --- Connection strings: passwords in mongodb / postgres / mysql / redis / amqp URLs ---

test('redacts passwords in connection strings, keeping scheme, user and host', () => {
  assert.equal(redact('mongodb://user:PASS@host'), 'mongodb://user:[PASSWORD]@host');
  assert.equal(redact('postgres://user:PASS@host:5432/db'), 'postgres://user:[PASSWORD]@host:5432/db');
  assert.equal(redact('mysql://user:PASS@host/db'), 'mysql://user:[PASSWORD]@host/db');
  assert.equal(redact('amqp://guest:PASS@host/vhost'), 'amqp://guest:[PASSWORD]@host/vhost');
  assert.equal(
    redact('mongodb+srv://user:PASS@cluster.example.net/db'),
    'mongodb+srv://user:[PASSWORD]@cluster.example.net/db'
  );
});

test('redacts connection-string passwords when there is no username (redis style)', () => {
  assert.equal(redact('redis://:PASS@host:6379'), 'redis://:[PASSWORD]@host:6379');
  assert.equal(redact('rediss://:PASS@host'), 'rediss://:[PASSWORD]@host');
});

test('redacts connection-string passwords containing special characters', () => {
  // A password containing '@' is redacted in full, not just up to the '@'.
  assert.equal(redact('postgres://user:p@ssw0rd@host/db'), 'postgres://user:[PASSWORD]@host/db');
  assert.equal(redact('mysql://user:p@ss:w0rd!#$%&*@host/db'), 'mysql://user:[PASSWORD]@host/db');
});

test('connection strings without a password are left alone', () => {
  assert.equal(redact('mongodb://user@host/db'), 'mongodb://user@host/db');
  assert.equal(redact('mongodb://host:27017/db'), 'mongodb://host:27017/db');
  assert.equal(redact('mongodb://user:@host/db'), 'mongodb://user:@host/db');
});

test('redacts every connection string in a longer string', () => {
  assert.equal(
    redact('primary mongodb://u1:PASS1@h1, replica postgres://u2:PASS2@h2 done'),
    'primary mongodb://u1:[PASSWORD]@h1, replica postgres://u2:[PASSWORD]@h2 done'
  );
});

test('connectionString respects except / keepLabels and is reported by findSensitive', () => {
  assert.equal(
    redact('mongodb://user:PASS@host', { except: ['connectionString', 'urlPassword'] }),
    'mongodb://user:PASS@host'
  );
  assert.equal(redact('mongodb://user:PASS@host', { keepLabels: false }), 'mongodb://user:[REDACTED]@host');
  const found = findSensitive('mongodb://user:PASS@host');
  assert.ok(found.some((f) => f.type === 'connectionString'));
});

// --- Issue #55: Sentry DSNs are redacted as DSNs, not mangled as emails ---

test('redacts a hosted Sentry DSN key as a DSN, keeping host and project id', () => {
  assert.equal(
    redact('DSN https://abc123def456@o12345.ingest.sentry.io/67890'),
    'DSN https://[DSN]@o12345.ingest.sentry.io/67890'
  );
});

test('redacts a Sentry DSN with a region subdomain as a DSN', () => {
  assert.equal(
    redact('https://pubkey@o12345.ingest.us.sentry.io/42'),
    'https://[DSN]@o12345.ingest.us.sentry.io/42'
  );
});

test('redacts a self-hosted Sentry DSN as a DSN', () => {
  assert.equal(
    redact('https://pubkey@sentry.example.com/7'),
    'https://[DSN]@sentry.example.com/7'
  );
});

test('an ordinary email is still redacted as an email, not a DSN', () => {
  assert.equal(redact('Contact ana@example.com'), 'Contact [EMAIL]');
  const found = findSensitive('Contact ana@example.com', { only: ['sentryDsn', 'email'] });
  assert.deepEqual(found.map((f) => f.type), ['email']);
});

test('a Sentry DSN is reported by findSensitive as sentryDsn', () => {
  const found = findSensitive('https://abc123@o1.ingest.sentry.io/9', { only: ['sentryDsn'] });
  assert.deepEqual(found.map((f) => f.type), ['sentryDsn']);
});

test('sentryDsn honours only / except / keepLabels', () => {
  const dsn = 'https://abc123@o1.ingest.sentry.io/9';
  assert.equal(redact(dsn, { except: ['sentryDsn'] }), 'https://[EMAIL]/9');
  assert.equal(redact(dsn, { keepLabels: false, replacement: '***' }), 'https://***@o1.ingest.sentry.io/9');
  assert.equal(redact(dsn, { labels: { sentryDsn: '[S]' } }), 'https://[S]@o1.ingest.sentry.io/9');
});

test('a URL with userinfo but no numeric project id is not mistaken for a DSN', () => {
  assert.deepEqual(findSensitive('https://user@example.com/path', { only: ['sentryDsn'] }), []);
  // The email inside it is still redacted as an email, not as a DSN.
  assert.equal(redact('https://user@example.com/path'), 'https://[EMAIL]/path');
});

test('a host that merely contains "sentry" is not a DSN', () => {
  // "notsentry" is one label, not the "sentry" label: the key falls back
  // to the email pattern, which redacts the whole address as an email.
  assert.equal(
    redact('see https://publickey@notsentry.example.com/42 end'),
    'see https://[EMAIL]/42 end'
  );
  assert.equal(
    redact('see https://publickey@sentry.example.com/42 end'),
    'see https://[DSN]@sentry.example.com/42 end'
  );
});


// --- Issue #36: GitHub fine-grained personal access tokens (github_pat_...) ---

// Deliberately obvious placeholder built at runtime (no key-shaped literal):
// a long run of letters, digits and underscores, like a real fine-grained PAT body.
const patBody = () => 'a1_'.repeat(20);

test('redacts a GitHub fine-grained personal access token as a token', () => {
  assert.equal(redact(`token github_pat_${patBody()}`), 'token [TOKEN]');
  const found = findSensitive(`token github_pat_${patBody()}`);
  assert.ok(found.some((f) => f.type === 'githubToken'));
});

test('a short github_pat_ string is not a token and stays untouched', () => {
  assert.equal(redact('token github_pat_short'), 'token github_pat_short');
  assert.deepEqual(findSensitive('token github_pat_short', { only: ['githubToken'] }), []);
  assert.equal(redact('see github_pat_ in the docs'), 'see github_pat_ in the docs');
});

test('classic GitHub tokens still redact beside fine-grained ones', () => {
  assert.equal(redact('token ghp_abcdefghij1234567890'), 'token [TOKEN]');
  assert.equal(
    redact(`a github_pat_${patBody()} and ghp_abcdefghij1234567890 here`),
    'a [TOKEN] and [TOKEN] here'
  );
});

// Placeholder-only URLs, assembled so no key-shaped literal is committed.
const webhook = (host = 'hooks.slack.com') =>
  `https://${host}/services/T00000000/B00000000/${'X'.repeat(24)}`;

test('redacts Slack incoming webhooks, including GovSlack', () => {
  assert.equal(redact(webhook()), '[WEBHOOK]');
  assert.equal(redact(webhook('hooks.slack-gov.com')), '[WEBHOOK]');
});

test('preserves ordinary Slack links and other hosts', () => {
  for (const text of [
    'https://slack.com/features',
    'https://hooks.slack.com/',
    'https://hooks.slack.com/services/T00000000/B00000000',
    'https://example.com/services/TEAM/CHANNEL/PLACEHOLDER',
    webhook('hooks.slack.com.example.com'),
    webhook('not-hooks.slack.com'),
  ]) {
    assert.equal(redact(text), text);
    assert.deepEqual(findSensitive(text), []);
  }
});

test('redacts each webhook without consuming log punctuation', () => {
  const text = `Notify <${webhook()}>, retry (${webhook('hooks.slack-gov.com')}).`;
  assert.equal(redact(text), 'Notify <[WEBHOOK]>, retry ([WEBHOOK]).');
});

test('redacts webhook strings inside nested log records', () => {
  const records = { records: [{ destination: webhook() }, [webhook()]] };
  assert.deepEqual(redactObject(records), {
    records: [{ destination: '[WEBHOOK]' }, ['[WEBHOOK]']],
  });
});

test('Slack webhook redaction honours pattern filters and replacement labels', () => {
  const url = webhook();
  assert.equal(redact(url, { only: ['slackWebhook'] }), '[WEBHOOK]');
  assert.equal(redact(url, { except: ['slackWebhook'] }), url);
  assert.equal(redact(url, { only: ['email'] }), url);
  assert.equal(redact(url, { labels: { slackWebhook: '[SLACK]' } }), '[SLACK]');
  assert.equal(redact(url, {
    labels: { slackWebhook: '[SLACK]' }, keepLabels: false, replacement: '***',
  }), '***');
});

test('findSensitive reports webhook type, full value, and log offset', () => {
  const url = webhook();
  assert.deepEqual(findSensitive(`send ${url}`, { only: ['slackWebhook'] }), [
    { type: 'slackWebhook', value: url, index: 5 },
  ]);
  assert.deepEqual(findSensitive(url, { except: ['slackWebhook'] }), []);
});

// --- Issue #44: Mailchimp API keys ---

// Obvious placeholder assembled at runtime so no key-shaped literal is
// committed (secret scanners flag those): 32 lowercase hex chars + suffix.
const mailchimpBody = () => 'a'.repeat(32);

test('redacts Mailchimp API keys as API keys', () => {
  const key = `${mailchimpBody()}-us14`;
  assert.equal(redact(`key ${key}`), 'key [API_KEY]');
  assert.equal(redact(`key ${mailchimpBody()}-us1`), 'key [API_KEY]');
  const found = findSensitive(`key ${key}`);
  assert.ok(found.some((f) => f.type === 'mailchimpKey' && f.value === key));
});

test('leaves a bare 32-character hex string (likely a hash) untouched', () => {
  const hash = mailchimpBody();
  assert.equal(redact(`hash ${hash}`), `hash ${hash}`);
  assert.deepEqual(findSensitive(hash, { only: ['mailchimpKey'] }), []);
});

test('Mailchimp key near misses stay untouched', () => {
  const short = `${'a'.repeat(31)}-us14`;
  const longSuffix = `${mailchimpBody()}-us140`;
  assert.equal(redact(`key ${short}`), `key ${short}`);
  assert.equal(redact(`key ${longSuffix}`), `key ${longSuffix}`);
});

test('mailchimpKey honours pattern filters and labels', () => {
  const key = `${mailchimpBody()}-us14`;
  assert.equal(redact(key, { except: ['mailchimpKey'] }), key);
  assert.equal(redact(key, { labels: { mailchimpKey: '[MC]' } }), '[MC]');
  assert.equal(redact(key, { keepLabels: false, replacement: '***' }), '***');
});

// --- Issue #50: Hugging Face tokens (hf_...) ---

// Obvious placeholder assembled at runtime so no token-shaped literal is
// committed: `hf_` followed by the documented 34-character body.
const hfToken = () => `hf_${'a'.repeat(34)}`;

test('redacts a Hugging Face token as a token', () => {
  const token = hfToken();
  assert.equal(redact(`token ${token}`), 'token [TOKEN]');
  const found = findSensitive(`token ${token}`);
  assert.ok(found.some((f) => f.type === 'huggingFaceToken' && f.value === token));
});

test('short hf_ strings and near misses stay untouched', () => {
  for (const text of [
    'hf_short',
    'hf_example',
    `hf_${'a'.repeat(33)}`,
    'see hf_ in the docs',
  ]) {
    assert.equal(redact(text), text);
    assert.deepEqual(findSensitive(text, { only: ['huggingFaceToken'] }), []);
  }
});

test('huggingFaceToken honours pattern filters and labels', () => {
  const token = hfToken();
  assert.equal(redact(token, { except: ['huggingFaceToken'] }), token);
  assert.equal(redact(token, { only: ['huggingFaceToken'] }), '[TOKEN]');
  assert.equal(redact(token, { labels: { huggingFaceToken: '[HF]' } }), '[HF]');
  assert.equal(redact(token, { keepLabels: false, replacement: '***' }), '***');
});

// Synthetic token bodies only; no live credentials are used in these tests.
test('redacts GitLab access tokens, including full base64url bodies', () => {
  const bodies = ['a'.repeat(20), 'Ab0_'.repeat(5), 'Ab0-'.repeat(5), 'Ab0_-'.repeat(8)];
  for (const body of bodies) {
    const token = 'glpat-' + body;
    assert.equal(redact(token), '[TOKEN]');
    assert.equal(redact(`Using (${token}), retry later.`), 'Using ([TOKEN]), retry later.');
    assert.deepEqual(findSensitive(`token ${token}`), [
      { type: 'gitlabToken', value: token, index: 6 },
    ]);
  }
});

test('GitLab token near misses stay untouched', () => {
  const inputs = [
    'glpat-',
    'glpat-short',
    'glpat-' + 'a'.repeat(19),
    'glpat-' + 'a'.repeat(19) + '.suffix',
    'xglpat-' + 'a'.repeat(20),
    '_glpat-' + 'a'.repeat(20),
    'GLPAT-' + 'a'.repeat(20),
  ];
  for (const input of inputs) {
    assert.equal(redact(input), input);
    assert.deepEqual(findSensitive(input), []);
  }
});

test('gitlabToken honours pattern filters and replacement labels', () => {
  const token = 'glpat-' + 'a'.repeat(20);
  assert.equal(redact(token, { except: ['gitlabToken'] }), token);
  assert.equal(redact(token, { only: ['gitlabToken'] }), '[TOKEN]');
  assert.equal(redact(token, { labels: { gitlabToken: '[GITLAB]' } }), '[GITLAB]');
  assert.equal(redact(token, { keepLabels: false, replacement: '***' }), '***');
  assert.deepEqual(findSensitive(token, { only: ['gitlabToken'] }), [
    { type: 'gitlabToken', value: token, index: 0 },
  ]);
  assert.deepEqual(findSensitive(token, { except: ['gitlabToken'] }), []);
});

// Synthetic DigitalOcean tokens; the bodies are assembled only for these tests.
for (const prefix of ['dop_v1_', 'doo_v1_', 'dor_v1_']) {
  test(`redacts DigitalOcean tokens with the ${prefix} prefix`, () => {
    for (const body of ['0123456789abcdef'.repeat(4), 'ABCDEF0123456789'.repeat(4)]) {
      const token = prefix + body;
      assert.equal(redact(token), '[TOKEN]');
      assert.equal(redact(`Using (${token}), retry later.`), 'Using ([TOKEN]), retry later.');
      assert.deepEqual(findSensitive(`using ${token}`), [
        { type: 'digitalOceanToken', value: token, index: 6 },
      ]);
    }
  });
}

test('DigitalOcean token near misses stay untouched', () => {
  const body = 'a'.repeat(64);
  const inputs = [
    body,
    'dox_v1_' + body,
    'dop_v2_' + body,
    'DOP_v1_' + body,
    'xdop_v1_' + body,
    '_dop_v1_' + body,
  ];
  for (const prefix of ['dop_v1_', 'doo_v1_', 'dor_v1_']) {
    inputs.push(prefix, prefix + 'short', prefix + 'a'.repeat(63), prefix + body + 'a');
    inputs.push(prefix + 'a'.repeat(63) + 'g', prefix + body + '_suffix');
  }
  for (const input of inputs) {
    assert.equal(redact(input), input);
    assert.deepEqual(findSensitive(input), []);
  }
});

test('redacts multiple DigitalOcean tokens in log text and nested records', () => {
  const tokens = ['dop_v1_', 'doo_v1_', 'dor_v1_'].map((prefix) => prefix + 'a'.repeat(64));
  assert.equal(redact(tokens.join(', ') + '.'), '[TOKEN], [TOKEN], [TOKEN].');
  assert.deepEqual(redactObject({ records: tokens.map((message) => ({ message })) }), {
    records: [{ message: '[TOKEN]' }, { message: '[TOKEN]' }, { message: '[TOKEN]' }],
  });
});

test('digitalOceanToken honours pattern filters and replacement labels', () => {
  const token = 'dop_v1_' + 'a'.repeat(64);
  assert.equal(redact(token, { only: ['digitalOceanToken'] }), '[TOKEN]');
  assert.equal(redact(token, { except: ['digitalOceanToken'] }), token);
  assert.equal(redact(token, { labels: { digitalOceanToken: '[DIGITALOCEAN]' } }), '[DIGITALOCEAN]');
  assert.equal(redact(token, {
    labels: { digitalOceanToken: '[DIGITALOCEAN]' }, keepLabels: false, replacement: '***',
  }), '***');
  assert.deepEqual(findSensitive(token, { only: ['digitalOceanToken'] }), [
    { type: 'digitalOceanToken', value: token, index: 0 },
  ]);
  assert.deepEqual(findSensitive(token, { except: ['digitalOceanToken'] }), []);
});

// Synthetic tokens in the formats accepted by the Supabase CLI.
for (const prefix of ['sbp_', 'sbp_oauth_', 'sbp_v0_']) {
  test(`redacts Supabase access tokens with the ${prefix} prefix`, () => {
    const token = prefix + '0123456789abcdef'.repeat(2) + '01234567';
    assert.equal(redact(token), '[TOKEN]');
    assert.equal(redact(`Using (${token}), retry later.`), 'Using ([TOKEN]), retry later.');
    assert.deepEqual(findSensitive(`using ${token}`), [
      { type: 'supabaseToken', value: token, index: 6 },
    ]);
  });
}

test('Supabase token near misses stay untouched', () => {
  const body = 'a'.repeat(40);
  const inputs = [body, 'SBP_' + body, 'sbp_v1_' + body, 'sbp_other_' + body];
  for (const prefix of ['sbp_', 'sbp_oauth_', 'sbp_v0_']) {
    inputs.push(prefix, prefix + 'short', prefix + 'a'.repeat(39), prefix + body + 'a');
    inputs.push(prefix + 'a'.repeat(39) + 'g', prefix + 'A'.repeat(40));
    inputs.push('x' + prefix + body, '_' + prefix + body, prefix + body + '_suffix');
  }
  for (const input of inputs) {
    assert.equal(redact(input), input);
    assert.deepEqual(findSensitive(input), []);
  }
});

test('redacts multiple Supabase tokens in text and nested records', () => {
  const tokens = ['sbp_', 'sbp_oauth_', 'sbp_v0_'].map((prefix) => prefix + 'a'.repeat(40));
  const text = tokens.join(', ') + '.';
  assert.equal(redact(text), '[TOKEN], [TOKEN], [TOKEN].');
  assert.deepEqual(findSensitive(text), tokens.map((token) => ({
    type: 'supabaseToken', value: token, index: text.indexOf(token),
  })));
  assert.deepEqual(redactObject({ records: tokens.map((message) => ({ message })) }), {
    records: [{ message: '[TOKEN]' }, { message: '[TOKEN]' }, { message: '[TOKEN]' }],
  });
});

test('supabaseToken honours pattern filters and replacement labels', () => {
  const token = 'sbp_' + 'a'.repeat(40);
  assert.equal(redact(token, { only: ['supabaseToken'] }), '[TOKEN]');
  assert.equal(redact(token, { except: ['supabaseToken'] }), token);
  assert.equal(redact(token, { labels: { supabaseToken: '[SUPABASE]' } }), '[SUPABASE]');
  assert.equal(redact(token, {
    labels: { supabaseToken: '[SUPABASE]' }, keepLabels: false, replacement: '***',
  }), '***');
  assert.deepEqual(findSensitive(token, { only: ['supabaseToken'] }), [
    { type: 'supabaseToken', value: token, index: 0 },
  ]);
  assert.deepEqual(findSensitive(token, { except: ['supabaseToken'] }), []);
});
