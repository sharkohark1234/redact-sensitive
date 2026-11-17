'use strict';

/**
 * redact-sensitive
 *
 * Redact sensitive data from text and logs before it leaves your app.
 * Zero dependencies. Works in Node.js and browsers (via bundlers).
 *
 *   const { redact } = require('redact-sensitive');
 *   redact('Contact me at ana@example.com or 555-123-4567');
 *   // 'Contact me at [EMAIL] or [PHONE]'
 */

const DEFAULT_REPLACEMENT = '[REDACTED]';

function luhnValid(digits) {
  let sum = 0;
  let doubleIt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (doubleIt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    doubleIt = !doubleIt;
  }
  return digits.length >= 13 && sum % 10 === 0;
}

function ipv4Valid(text) {
  const parts = text.split('.');
  return (
    parts.length === 4 &&
    parts.every((part) => {
      const n = Number(part);
      return n >= 0 && n <= 255 && String(n) === part;
    })
  );
}

// Each group is 1-4 hex digits; eight groups, or fewer with exactly one `::`.
// A dotted IPv4 tail counts as two groups. A bare `::` is not redacted, since
// in prose it is far more often punctuation than the unspecified address.
function ipv6Valid(text) {
  if (text === '::') return false;
  let address = text;
  if (address.includes('.')) {
    const cut = address.lastIndexOf(':') + 1;
    if (!ipv4Valid(address.slice(cut))) return false;
    address = address.slice(0, cut) + '0:0';
  }
  const halves = address.split('::');
  if (halves.length > 2) return false;
  const groups = halves.flatMap((half) => (half === '' ? [] : half.split(':')));
  if (!groups.every((group) => /^[0-9A-Fa-f]{1,4}$/.test(group))) return false;
  return halves.length === 2 ? groups.length <= 7 : groups.length === 8;
}

const PATTERNS = [
  {
    name: 'urlPassword',
    label: '[PASSWORD]',
    // https://user:password@host — redact only the password part.
    regex: /(\/\/[^/\s:@]+:)([^/\s@]+)(@)/g,
    replacement: '$1[PASSWORD]$3',
  },
  {
    name: 'email',
    label: '[EMAIL]',
    regex: /(?<![A-Za-z0-9._%+\[\]])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
  },
  {
    name: 'awsAccessKey',
    label: '[AWS_KEY]',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    name: 'githubToken',
    label: '[TOKEN]',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g,
  },
  {
    name: 'slackToken',
    label: '[TOKEN]',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    name: 'openaiKey',
    label: '[API_KEY]',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/g,
  },
  {
    name: 'privateKey',
    label: '[PRIVATE_KEY]',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    name: 'jwt',
    label: '[TOKEN]',
    regex: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  },
  {
    name: 'creditCard',
    label: '[CARD]',
    // 13-19 digits, optionally grouped with spaces or dashes. Luhn-checked below.
    regex: /\b(?:\d[ -]?){12,18}\d\b/g,
    validate: (match) => luhnValid(match.replace(/[ -]/g, '')),
  },
  {
    name: 'ssn',
    label: '[SSN]',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    name: 'phone',
    label: '[PHONE]',
    // +1 555-123-4567, (555) 123-4567, 555-123-4567, +91 98765 43210
    regex: /(?:\+\d{1,3}[\s-]?)?(?:\(\d{2,4}\)[\s-]?|\d{2,4}[\s-])?\d{3,4}[\s-]\d{4}\b/g,
    validate: (match) => match.replace(/\D/g, '').length >= 7,
  },
  {
    name: 'ipv6',
    label: '[IP]',
    // Full (2001:0db8:…:7334), compressed (2001:db8::1, ::1, fe80::) and
    // IPv4-mapped (::ffff:192.0.2.1) forms. Runs before ipv4 so a mapped
    // address is replaced whole. The look-arounds keep it from starting or
    // ending inside a word, so `std::vector` and `Foo::Bar` are not candidates.
    regex: /(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,8}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{1,4})?(?![\w:]|\.\d)/g,
    validate: ipv6Valid,
  },
  {
    name: 'ipv4',
    label: '[IP]',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    validate: ipv4Valid,
  },
  {
    name: 'genericApiKey',
    label: '[API_KEY]',
    regex: /\b(?:api[_-]?key|apikey|secret|token|passwd|password)\s*[:=]\s*['"]?([A-Za-z0-9_\-./]{8,})['"]?/gi,
    replacement: (match) => match.replace(/([:=]\s*['"]?)[A-Za-z0-9_\-./]{8,}(['"]?)/, '$1[API_KEY]$2'),
  },
];

function redact(input, options = {}) {
  if (input === null || input === undefined) return input;
  if (typeof input !== 'string') return input;

  const replacement = options.replacement || DEFAULT_REPLACEMENT;
  const enabled = new Set(options.only || PATTERNS.map((p) => p.name));
  const disabled = new Set(options.except || []);
  let out = input;

  for (const pattern of PATTERNS) {
    if (!enabled.has(pattern.name) || disabled.has(pattern.name)) continue;
    const label = options.keepLabels === false ? replacement : pattern.label;
    if (typeof pattern.replacement === 'function') {
      out = out.replace(pattern.regex, pattern.replacement);
    } else if (typeof pattern.replacement === 'string') {
      out = out.replace(pattern.regex, pattern.replacement);
    } else if (pattern.validate) {
      out = out.replace(pattern.regex, (match) => (pattern.validate(match) ? label : match));
    } else {
      out = out.replace(pattern.regex, label);
    }
  }

  for (const custom of options.custom || []) {
    const regex = custom instanceof RegExp ? custom : new RegExp(custom.pattern, custom.flags || 'g');
    out = out.replace(regex, custom.replacement || replacement);
  }

  return out;
}

function redactObject(value, options = {}) {
  if (typeof value === 'string') return redact(value, options);
  if (Array.isArray(value)) return value.map((item) => redactObject(item, options));
  if (isPlainObject(value)) {
    const out = {};
    for (const [key, val] of Object.entries(value)) {
      // A value stored under a sensitive key name is a secret, whatever
      // its type — replace it outright instead of recursing into it.
      const label = sensitiveKeyLabel(key, options);
      out[key] = label !== null ? label : redactObject(val, options);
    }
    return out;
  }
  return value;
}

// Only plain objects (created with {} or Object.create(null)) are safe
// to rebuild key by key. Anything else — Date, RegExp, Buffer, class
// instances — keeps its own internal state, which Object.entries would
// not preserve, so it is passed through unchanged.
function isPlainObject(value) {
  if (!value || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

// Key names whose values are always secrets. Matching is case-insensitive
// and ignores '_'/'-' separators, so `apiKey`, `api_key` and `API-KEY`
// all match. Contributors: extend this map to cover new key names.
const SENSITIVE_KEYS = new Map([
  ['password', '[PASSWORD]'],
  ['passwd', '[PASSWORD]'],
  ['pwd', '[PASSWORD]'],
  ['secret', '[SECRET]'],
  ['apikey', '[API_KEY]'],
  ['accesskey', '[API_KEY]'],
  ['token', '[TOKEN]'],
  ['auth', '[TOKEN]'],
  ['authorization', '[TOKEN]'],
  ['privatekey', '[PRIVATE_KEY]'],
  ['clientsecret', '[SECRET]'],
]);

function normalizeKeyName(key) {
  return String(key).toLowerCase().replace(/[_-]/g, '');
}

// Returns the replacement label for a sensitive key name, or null if the
// key is not sensitive. `options.sensitiveKeys` adds extra key names
// (matched the same way) that are replaced with '[REDACTED]'.
function sensitiveKeyLabel(key, options = {}) {
  const name = normalizeKeyName(key);
  if (SENSITIVE_KEYS.has(name)) {
    return options.keepLabels === false
      ? options.replacement || DEFAULT_REPLACEMENT
      : SENSITIVE_KEYS.get(name);
  }
  const extra = (options.sensitiveKeys || []).map(normalizeKeyName);
  if (extra.includes(name)) return options.replacement || DEFAULT_REPLACEMENT;
  return null;
}

function findSensitive(input) {
  if (typeof input !== 'string') return [];
  const found = [];
  for (const pattern of PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;
    while ((match = regex.exec(input)) !== null) {
      if (pattern.validate && !pattern.validate(match[0])) continue;
      found.push({ type: pattern.name, value: match[0] });
      if (match[0].length === 0) regex.lastIndex++;
    }
  }
  return found;
}

module.exports = { redact, redactObject, findSensitive, PATTERNS, SENSITIVE_KEYS };
