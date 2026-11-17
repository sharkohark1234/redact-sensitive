# redact-sensitive

Redact emails, phone numbers, API keys, credit cards and other sensitive data from text and logs — before they leave your app.

Zero dependencies. Works in Node.js 16+ and in browsers via bundlers. TypeScript types included.

```js
const { redact } = require('redact-sensitive');

redact('Contact me at ana@example.com or 555-123-4567');
// 'Contact me at [EMAIL] or [PHONE]'

redact('Card 4111 1111 1111 1111, key sk-abcdefghij1234567890abcd');
// 'Card [CARD], key [API_KEY]'
```

## Why

Logs, error reports and support tickets routinely leak the very data they were meant to debug. One `console.log(user)` can put an email, a token or a card number into a log store, a crash report or a shared screenshot. `redact-sensitive` is a one-line safety net: run untrusted text through it before logging, storing or sending it anywhere.

## Install

```bash
npm install redact-sensitive
```

## Usage

### `redact(text, options?)`

```js
const { redact, redactObject, findSensitive } = require('redact-sensitive');

redact('Email ana@example.com, IP 203.0.113.42');
// 'Email [EMAIL], IP [IP]'

// Redact only emails
redact('a@b.com 555-123-4567', { only: ['email'] });
// '[EMAIL] 555-123-4567'

// Use one replacement for everything
redact('a@b.com', { keepLabels: false, replacement: '***' });
// '***'

// Add your own pattern
redact('order #12345', {
  custom: [{ pattern: '#\\d+', replacement: '[ORDER]' }],
});
```

### `redactObject(value, options?)`

Recursively redacts strings inside objects and arrays. Useful for sanitising a whole log payload:

```js
redactObject({ user: { email: 'ana@example.com' }, tags: ['x@y.com'] });
// { user: { email: '[EMAIL]' }, tags: ['[EMAIL]'] }

// Values stored under a sensitive key name are replaced outright,
// whatever their type — even when they look like plain text:
redactObject({ password: 'hunter2', apiKey: 'abc123secret', user: 'ana' });
// { password: '[PASSWORD]', apiKey: '[API_KEY]', user: 'ana' }

// Add your own sensitive key names with `sensitiveKeys`:
redactObject({ myPhrase: 'shh' }, { sensitiveKeys: ['myPhrase'] });
// { myPhrase: '[REDACTED]' }
```

Date, RegExp and other non-plain objects pass through unchanged — only plain objects, arrays and strings are rebuilt.

### `findSensitive(text)`

Returns what would be redacted, without changing the text:

```js
findSensitive('mail a@b.com, card 4111111111111111');
// [{ type: 'email', value: 'a@b.com' }, { type: 'creditCard', value: '4111111111111111' }]
```

## What is redacted

| Type | Example |
| --- | --- |
| Email | `ana@example.com` → `[EMAIL]` |
| Phone | `+1 555-123-4567`, `+91 98765 43210` → `[PHONE]` |
| Credit card | Luhn-validated, 13–19 digits → `[CARD]` |
| API keys | GitHub `ghp_…`, OpenAI `sk-…`, AWS `AKIA…`, Slack `xoxb-…` → `[TOKEN]` / `[API_KEY]` |
| JWT | `eyJ…` → `[TOKEN]` |
| Private key blocks | `-----BEGIN PRIVATE KEY-----` → `[PRIVATE_KEY]` |
| SSN | `123-45-6789` → `[SSN]` |
| IPv4 | `203.0.113.42` → `[IP]` |
| IPv6 | `2001:db8::1`, `::1`, `::ffff:192.0.2.1` → `[IP]` |
| URL passwords | `https://user:pass@host` → `https://user:[PASSWORD]@host` |
| `key = value` secrets | `api_key = abc123…` → `api_key = [API_KEY]` |

Credit cards are only redacted when they pass the Luhn check, so a random 16-digit order number is left alone. Phone numbers need at least 7 digits.

## What this is not

This is a safety net, not a guarantee. No pattern list can catch every secret in every format, and redaction happens after the secret already exists in memory. Treat it as one layer: keep real secrets out of logs in the first place, rotate any secret that was ever logged, and never rely on redaction alone for compliance.

## Contributing

Contributions are welcome — especially new redaction patterns. See [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues are labelled `good first issue`.

## License

MIT. See [LICENSE](LICENSE).
