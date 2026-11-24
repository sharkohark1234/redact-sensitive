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

// IBAN length for each country in the SWIFT IBAN registry.
const IBAN_LENGTHS = {
  AD: 24, AE: 23, AL: 28, AT: 20, AX: 18, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22,
  BI: 27, BR: 29, BY: 28, CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DJ: 27, DK: 18,
  DO: 28, EE: 20, EG: 29, ES: 24, FI: 18, FK: 18, FO: 18, FR: 27, GB: 22, GE: 22,
  GF: 27, GI: 23, GL: 18, GP: 27, GR: 27, GT: 28, HN: 28, HR: 21, HU: 28, IE: 22,
  IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LC: 32, LI: 21,
  LT: 20, LU: 20, LV: 21, LY: 25, MC: 27, MD: 24, ME: 22, MF: 27, MK: 19, MN: 20,
  MQ: 27, MR: 27, MT: 31, MU: 30, NC: 27, NI: 28, NL: 18, NO: 15, OM: 23, PF: 27,
  PK: 24, PL: 28, PM: 27, PS: 29, PT: 25, QA: 29, RE: 27, RO: 24, RS: 22, RU: 33,
  SA: 24, SC: 31, SD: 18, SE: 24, SI: 19, SK: 24, SM: 27, SO: 23, ST: 25, SV: 28,
  TF: 27, TL: 23, TN: 24, TR: 26, UA: 29, VA: 22, VG: 24, WF: 27, XK: 20, YE: 30,
  YT: 27,
};

// Build one alternative per length so a match stops exactly where the IBAN
// ends. E.g. for 16 (BE): BE\d{2}(?: ?[A-Z0-9]{4}){3}, so in
// "BE68 5390 0754 7034 CODE" the following word is never pulled in.
function buildIbanRegex() {
  const countriesByLength = {};
  for (const [country, length] of Object.entries(IBAN_LENGTHS)) {
    (countriesByLength[length] = countriesByLength[length] || []).push(country);
  }
  const alternatives = Object.entries(countriesByLength).map(([length, countries]) => {
    const rest = Number(length) - 4;
    const fullGroups = Math.floor(rest / 4);
    const remainder = rest % 4;
    return (
      `(?:${countries.join('|')})\\d{2}(?: ?[A-Z0-9]{4}){${fullGroups}}` +
      (remainder ? `(?: ?[A-Z0-9]{${remainder}})` : '')
    );
  });
  return new RegExp(`\\b(?:${alternatives.join('|')})\\b`, 'g');
}

// ISO 13616 mod-97 check: move the first 4 chars to the end, turn letters
// into numbers (A=10 ... Z=35), and the result mod 97 must equal 1.
function ibanValid(match) {
  const iban = match.replace(/ /g, '');
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const value = ch >= 'A' && ch <= 'Z' ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of value) {
      remainder = (remainder * 10 + Number(digit)) % 97;
    }
  }
  return remainder === 1;
}

// Query-string parameter names whose values are secrets, mapped to the
// label that replaces the value. Looked up by the normalised param name
// (lower-case, '_'/'-' stripped), so `access_token`, `access-token` and
// `accessToken` all map to the same label.
const QUERY_PARAM_LABELS = {
  token: '[TOKEN]',
  accesstoken: '[TOKEN]',
  refreshtoken: '[TOKEN]',
  idtoken: '[TOKEN]',
  auth: '[TOKEN]',
  authorization: '[TOKEN]',
  session: '[TOKEN]',
  sessionid: '[TOKEN]',
  apikey: '[API_KEY]',
  secret: '[SECRET]',
  clientsecret: '[SECRET]',
  password: '[PASSWORD]',
  passwd: '[PASSWORD]',
  pwd: '[PASSWORD]',
};

// Cookie names whose values are session identifiers, matched by the
// normalised name (lower-case, '_'/'-' stripped) — the same care as
// QUERY_PARAM_LABELS — so `session_id`, `session-id` and `sessionId`
// all match, while `mysession` or `sessionid2` do not.
const SESSION_COOKIE_NAMES = new Set([
  'session',
  'sessionid',
  'sessiontoken',
  'sid',
  'auth',
  'authtoken',
  'token',
  'accesstoken',
  'refreshtoken',
  'idtoken',
]);

// Redact the values of session-like cookies inside one Cookie /
// Set-Cookie header value, keeping everything else readable: cookie
// names, harmless cookies (`theme=dark`), flag attributes with no value
// (`HttpOnly`, `Secure`) and attributes with harmless values
// (`Path=/`, `Expires=...`, `Max-Age=3600`, `SameSite=Lax`).
// Pairs are split on ';'; a session value runs to the next ';', or to a
// ',' when headers are comma-joined on one log line (commas are not
// valid in cookie values, so a session value never contains one).
// An empty value has nothing to leak and is left alone.
function redactCookieHeaderValue(headerValue, label) {
  return headerValue
    .split(';')
    .map((part) => {
      const eq = part.indexOf('=');
      if (eq === -1) return part;
      if (!SESSION_COOKIE_NAMES.has(normalizeKeyName(part.slice(0, eq).trim()))) return part;
      const raw = part.slice(eq + 1);
      const leading = (raw.match(/^\s*/) || [''])[0];
      const trailing = (raw.match(/\s*$/) || [''])[0];
      const core = raw.slice(leading.length, raw.length - trailing.length);
      if (core === '') return part;
      let value;
      let rest = '';
      if (core.startsWith('"')) {
        const closing = core.indexOf('"', 1);
        if (closing === -1) return part;
        value = `"${label}"`;
        rest = core.slice(closing + 1);
      } else {
        // An unquoted cookie value is a run of cookie-octets (RFC 6265):
        // a double-quote cannot occur inside it, so a '"' after the value
        // is the closing quote of surrounding log syntax (e.g. a JSON
        // string), not part of the value — stop there too, keeping it
        // untouched. Same for ',' separating combined cookie headers.
        const comma = core.indexOf(',');
        const quote = core.indexOf('"');
        const cut = [comma, quote].filter((i) => i !== -1);
        const end = cut.length === 0 ? -1 : Math.min(...cut);
        const valuePart = end === -1 ? core : core.slice(0, end);
        if (valuePart === '') return part;
        value = label;
        rest = end === -1 ? '' : core.slice(end);
      }
      return `${part.slice(0, eq + 1)}${leading}${value}${rest}${trailing}`;
    })
    .join(';');
}

const PATTERNS = [
  {
    name: 'connectionString',
    label: '[PASSWORD]',
    // Database / cache / queue connection strings:
    // mongodb://user:pass@host, postgres://user:pass@host:5432/db,
    // redis://:pass@host (no username), amqp://user:pass@host/vhost.
    // Only the password is replaced; scheme, user and host stay readable.
    // The userinfo is captured greedily up to the last '@' before the
    // host, because a password may itself contain '@' or ':' — the
    // simpler urlPassword shape below stops at the first '@' and cannot
    // handle a missing username, so this pattern runs first.
    regex: /\b((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql2?|rediss?|amqps?):\/\/)([^\s/,]+)@([^\s/:,]+)/gi,
    // Receives the effective label as an extra final argument from
    // redact(), so keepLabels / options.labels are honoured here too.
    replacement: (match, prefix, userinfo, host, _offset, _string, label) => {
      const colon = userinfo.indexOf(':');
      // No ':' means userinfo is a bare username with no password, and a
      // trailing ':' means an empty password — nothing to redact.
      if (colon === -1 || colon === userinfo.length - 1) return match;
      return `${prefix}${userinfo.slice(0, colon + 1)}${label || '[PASSWORD]'}@${host}`;
    },
  },
  {
    name: 'urlPassword',
    label: '[PASSWORD]',
    // https://user:password@host — redact only the password part.
    regex: /(\/\/[^/\s:@]+:)([^/\s@]+)(@)/g,
    replacement: '$1[PASSWORD]$3',
  },
  {
    name: 'slackWebhook',
    label: '[WEBHOOK]',
    // Incoming webhook URLs contain the bearer secret in their three-part
    // /services/ path. Match only Slack's webhook hosts (including GovSlack),
    // so ordinary Slack pages and similarly named hosts stay readable.
    regex: /\bhttps:\/\/hooks\.slack(?:-gov)?\.com\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+/gi,
  },
  {
    name: 'urlQuerySecret',
    label: '[REDACTED]',
    // Secrets passed as URL query values: ?token=abc123&user=ana redacts
    // only the value of a sensitive param, never the param name or other
    // params. The label depends on the param name (see QUERY_PARAM_LABELS),
    // so this pattern uses `labelFor` instead of a fixed label.
    regex: /([?&](?:access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|client[_-]?secret|session[_-]?id|token|secret|auth|authorization|password|passwd|pwd|session)=)([^&\s"'<>#,;]+)/gi,
    labelFor: (match, groups) => {
      const prefix = groups[0];
      const name = prefix.slice(1, -1).toLowerCase().replace(/[_-]/g, '');
      return [prefix, QUERY_PARAM_LABELS[name] || '[REDACTED]'];
    },
  },
  {
    name: 'authHeader',
    label: '[TOKEN]',
    // Authorization: Bearer <token> / Basic <base64 user:pass> in log text.
    // Only the credential is replaced; the header name and scheme stay.
    // Other schemes (Negotiate, Digest, ...) are left alone: their tokens
    // are session-bound challenge responses, not reusable static credentials.
    regex: /\b(Authorization|Proxy-Authorization)(:)([ \t]*)(Bearer|Basic)([ \t]+)([^\s"'<>,;}\]]+)/gi,
    labelFor: (match, groups) => {
      const [header, colon, afterColon, scheme, afterScheme] = groups;
      const label = scheme.toLowerCase() === 'basic' ? '[CREDENTIALS]' : '[TOKEN]';
      return [header + colon + afterColon + scheme + afterScheme, label];
    },
  },
  {
    name: 'sessionCookie',
    label: '[TOKEN]',
    // Session cookie values in `Cookie` / `Set-Cookie` header lines:
    // `Cookie: session=<id>; theme=dark` redacts only the value of a
    // session-like cookie name (see SESSION_COOKIE_NAMES). Cookie names,
    // harmless cookies and Set-Cookie attributes stay readable.
    // Runs before genericApiKey / email / phone so a session value is
    // never mangled by another pattern first.
    regex: /\b((?:Set-Cookie|Cookie):[ \t]*)([^\r\n]*)/gi,
    // Receives the effective label as an extra final argument from
    // redact(), so keepLabels / options.labels are honoured here too.
    replacement: (match, prefix, headerValue, _offset, _string, label) =>
      prefix + redactCookieHeaderValue(headerValue, label || '[TOKEN]'),
  },
  {
    name: 'sentryDsn',
    label: '[DSN]',
    // A Sentry DSN is https://<public-key>@<sentry-host>/<numeric-project-id>.
    // The host has "sentry" as a whole dot-separated label (ingest.sentry.io,
    // regional subdomains such as ingest.us.sentry.io, or a self-hosted
    // sentry.example.com) — a host that merely contains "sentry" inside
    // another label (notsentry.example.com) is not a DSN. Running before
    // `email` so the key is redacted as a DSN instead of being mangled by
    // the email pattern, which would also hide the host. Only the key is
    // replaced; scheme, host and project id stay readable.
    regex: /\b(https?:\/\/)([^/\s:@]+)@((?:[A-Za-z0-9-]+\.)*sentry(?:\.[A-Za-z0-9-]+)*)\/(\d+)/gi,
    // Receives the effective label as an extra final argument from redact(),
    // so keepLabels / options.labels are honoured here too.
    replacement: (match, scheme, key, host, projectId, _offset, _string, label) =>
      `${scheme}${label || '[DSN]'}@${host}/${projectId}`,
  },
  {
    name: 'email',
    label: '[EMAIL]',
    // The lookbehind lists every local-part character (including `-`) so a match
    // can only start at the beginning of a run; otherwise a long digit-dash run
    // with no `@` is re-scanned from every position (quadratic).
    regex: /(?<![A-Za-z0-9._%+\[\]-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
  },
  {
    name: 'awsAccessKey',
    label: '[AWS_KEY]',
    // AKIA = long-term access key id; ASIA = temporary session credentials.
    // Allow suffixes longer than the standard 16 chars so over-long ids still redact.
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16,}\b/g,
  },
  {
    name: 'mailchimpKey',
    label: '[API_KEY]',
    // Mailchimp API keys are 32 lowercase hex characters followed by a
    // data-centre suffix such as -us14. The suffix is what makes the shape
    // distinctive: a bare 32-character hex string is just as likely to be a
    // hash, so it is left untouched. Runs with the other token patterns,
    // before genericApiKey, so `api_key = <key>` is reported as this type.
    regex: /\b[0-9a-f]{32}-us\d{1,2}\b/g,
  },
  {
    name: 'githubToken',
    label: '[TOKEN]',
    // Classic tokens: ghp_/gho_/ghu_/ghs_/ghr_ + 20 or more alphanumerics.
    // Fine-grained tokens: github_pat_ + a long run of letters, digits and
    // underscores (22 chars, an underscore, then 59 chars in the real format).
    regex: /\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
  },
  {
    name: 'gitlabToken',
    label: '[TOKEN]',
    // GitLab's default glpat- prefix followed by 20+ base64url characters.
    // Consume the full body, including trailing hyphens.
    regex: /\bglpat-[A-Za-z0-9_-]{20,}/g,
  },
  {
    name: 'digitalOceanToken',
    label: '[TOKEN]',
    // Personal access, OAuth access and refresh tokens use distinct prefixes
    // followed by 64 hex characters. Do not match short or overlong bodies.
    regex: /\bdo[por]_v1_[0-9a-fA-F]{64}\b/g,
  },
  {
    name: 'huggingFaceToken',
    label: '[TOKEN]',
    // Hugging Face user and organisation tokens: the literal `hf_` prefix
    // followed by 34 alphanumeric characters. The exact body length keeps
    // short placeholder strings such as `hf_example` untouched.
    regex: /\bhf_[A-Za-z0-9]{34}\b/g,
  },
  {
    name: 'supabaseToken',
    label: '[TOKEN]',
    // The CLI accepts sbp_, sbp_oauth_ and sbp_v0_ followed by 40 lowercase
    // hex characters. Keep incomplete tokens and longer words untouched.
    regex: /\bsbp_(?:oauth_|v0_)?[a-f0-9]{40}\b/g,
  },
  {
    name: 'slackToken',
    label: '[TOKEN]',
    // Slack tokens use several prefixes: xoxb/xoxa/xoxp/xoxr/xoxs (classic)
    // and xoxe- (newer enterprise/token format).
    regex: /\bxox[baprse]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    name: 'openaiKey',
    label: '[API_KEY]',
    // sk-<body>, sk-proj-<body> (project keys) and sk-svcacct-<body> (service
    // account keys) are all API keys.
    regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9]{20,}\b/g,
  },
  {
    name: 'anthropicApiKey',
    label: '[API_KEY]',
    // Anthropic Claude API keys: sk-ant-api03- and sk-ant-admin01- followed by
    // 93 base64url characters and the literal suffix AA (95 chars total body).
    regex: /(?<![A-Za-z0-9_-])sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA(?![A-Za-z0-9_-])/g,
  },
  {
    name: 'stripeKey',
    label: '[API_KEY]',
    // Stripe secret keys: sk_live_... / sk_test_... plus restricted keys
    // rk_live_... / rk_test_... (24+ chars after the prefix). Publishable
    // keys (pk_live_... / pk_test_...) are not secrets and are left alone.
    regex: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{24,}\b/g,
  },
  {
    name: 'privateKey',
    label: '[PRIVATE_KEY]',
    // A complete BEGIN...END block is replaced whole. If there is no END line
    // (a log line cut off mid-key), the header plus the base64 lines that
    // follow it (16+ chars each, so ordinary words are not swallowed) are replaced.
    regex: /-----BEGIN (?:ENCRYPTED |RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----(?:[\s\S]*?-----END (?:ENCRYPTED |RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----|(?:\r?\n[A-Za-z0-9+/]{16,}={0,2})*)/g,
  },
  {
    name: 'jwt',
    label: '[TOKEN]',
    regex: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  },
  {
    name: 'iban',
    label: '[IBAN]',
    // DE89 3704 0044 0532 0130 00 or DE89370400440532013000. Exact length per
    // country, then mod-97 checked below.
    // Runs before creditCard and phone so their patterns don't grab the digit groups.
    regex: buildIbanRegex(),
    validate: ibanValid,
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
    name: 'indianPan',
    label: '[PAN]',
    // Indian Permanent Account Number: five letters, four digits, one letter.
    regex: /\b[A-Z]{5}\d{4}[A-Z]\b/g,
  },
  {
    name: 'phone',
    label: '[PHONE]',
    // +1 555-123-4567, (555) 123-4567, 555-123-4567, +91 98765 43210
    regex: /(?:\+\d{1,3}[\s-]?)?(?:\(\d{2,4}\)[\s-]?|\d{2,4}[\s-])?\d{3,4}[\s-]\d{4}\b/g,
    validate: (match) => match.replace(/\D/g, '').length >= 7,
  },
  {
    name: 'ipv4',
    label: '[IP]',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    validate: (match) =>
      match.split('.').every((part) => {
        const n = Number(part);
        return n >= 0 && n <= 255 && String(n) === part;
      }),
  },
  {
    name: 'genericApiKey',
    label: '[API_KEY]',
    // The value class includes '+' and '=' because real secret values are
    // often base64 (AWS secret access keys are), and base64 uses both —
    // without them only the first run was replaced and the tail leaked (#35).
    // Quotes are not in the class, so a closing quote is never swallowed.
    regex: /\b(?:api[_-]?key|apikey|(?:aws[_-]?)?secret[_-]?access[_-]?key|secret|token|passwd|password)\s*[:=]\s*['"]?([A-Za-z0-9_\-./+=]{8,})['"]?/gi,
    // Receives the effective label as an extra final argument from redact(),
    // so keepLabels / options.labels are honoured here too.
    replacement: (match, _value, _offset, _string, label) =>
      match.replace(/([:=]\s*['"]?)[A-Za-z0-9_\-./+=]{8,}(['"]?)/, `$1${label || '[API_KEY]'}$2`),
  },
];

function validateOptions(options) {
  if (!options.only && !options.except && !options.labels) return;
  const patternNames = PATTERNS.map((pattern) => pattern.name);
  for (const option of ['only', 'except', 'labels']) {
    const validNames = option === 'labels' ? [...patternNames, ...SENSITIVE_KEYS.keys()] : patternNames;
    const valid = new Set(validNames);
    const names = option === 'labels' ? Object.keys(options.labels || {}) : options[option] || [];
    for (const name of names) {
      if (!valid.has(name)) {
        throw new RangeError(`Unknown name "${name}" in options.${option}. Valid names: ${validNames.join(', ')}`);
      }
    }
  }
}

function redact(input, options = {}) {
  validateOptions(options);
  if (input === null || input === undefined) return input;
  if (typeof input !== 'string') return input;

  const replacement = options.replacement || DEFAULT_REPLACEMENT;
  const enabled = new Set(options.only || PATTERNS.map((p) => p.name));
  const disabled = new Set(options.except || []);
  let out = input;

  for (const pattern of PATTERNS) {
    if (!enabled.has(pattern.name) || disabled.has(pattern.name)) continue;
    // Per-type label override, e.g. { labels: { email: '[E-MAIL]' } }.
    // keepLabels: false still wins over everything.
    const label =
      options.keepLabels === false
        ? replacement
        : (options.labels || {})[pattern.name] || pattern.label;
    if (typeof pattern.replacement === 'function') {
      // Function replacements receive the effective label as an extra
      // final argument, so they can honour keepLabels / options.labels.
      out = out.replace(pattern.regex, (...args) => pattern.replacement(...args, label));
    } else if (typeof pattern.replacement === 'string') {
      // String replacements carry the pattern's own label as a placeholder.
      out = out.replace(pattern.regex, pattern.replacement.split(pattern.label).join(label));
    } else if (pattern.labelFor) {
      // Patterns whose label depends on what matched (query param name,
      // auth scheme) and where only the secret part is replaced.
      // labelFor(match, groups) returns [textToKeep, labelForTheSecret].
      out = out.replace(pattern.regex, (match, ...groups) => {
        const [keep, matchLabel] = pattern.labelFor(match, groups);
        const effectiveLabel =
          options.keepLabels === false ? replacement : (options.labels || {})[pattern.name] || matchLabel;
        return keep + effectiveLabel;
      });
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

const DEFAULT_MAX_DEPTH = 100;

function redactObject(value, options = {}) {
  validateOptions(options);
  return redactObjectInternal(value, options, new Set(), 0);
}

// Internal worker for redactObject. `seen` holds only the ancestors of
// the value currently being walked (added before recursing, removed
// after), so a genuinely circular reference becomes '[Circular]' while
// the same object shared in two non-circular places is redacted twice.
// `depth` counts nesting levels; past `options.maxDepth` (default 100)
// the value is replaced with '[DEPTH_LIMIT]' instead of recursing until
// the stack overflows.
function redactObjectInternal(value, options, seen, depth) {
  if (typeof value === 'string') return redact(value, options);
  if (Array.isArray(value)) {
    if (seen.has(value)) return '[Circular]';
    if (depth > maxDepth(options)) return '[DEPTH_LIMIT]';
    seen.add(value);
    const out = value.map((item) => redactObjectInternal(item, options, seen, depth + 1));
    seen.delete(value);
    return out;
  }
  if (isPlainObject(value)) {
    if (seen.has(value)) return '[Circular]';
    if (depth > maxDepth(options)) return '[DEPTH_LIMIT]';
    seen.add(value);
    const out = {};
    for (const [key, val] of Object.entries(value)) {
      // A value stored under a sensitive key name is a secret, whatever
      // its type — replace it outright instead of recursing into it.
      const label = sensitiveKeyLabel(key, options);
      out[key] = label !== null ? label : redactObjectInternal(val, options, seen, depth + 1);
    }
    // Object.entries skips symbol keys, which used to drop those
    // properties entirely (#23). Carry enumerable symbol keys over with
    // the same rules as string keys: the symbol's description is checked
    // against the sensitive key names, so Symbol('password') redacts
    // outright, and any other value is recursed into as usual.
    // Non-enumerable properties are not copied, for symbol keys exactly
    // as for string keys.
    for (const sym of Object.getOwnPropertySymbols(value)) {
      if (!Object.prototype.propertyIsEnumerable.call(value, sym)) continue;
      const label = sym.description ? sensitiveKeyLabel(sym.description, options) : null;
      out[sym] = label !== null ? label : redactObjectInternal(value[sym], options, seen, depth + 1);
    }
    seen.delete(value);
    return out;
  }
  return value;
}

function maxDepth(options) {
  const limit = options.maxDepth;
  return typeof limit === 'number' && Number.isFinite(limit) && limit >= 0
    ? Math.floor(limit)
    : DEFAULT_MAX_DEPTH;
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
    if (options.keepLabels === false) return options.replacement || DEFAULT_REPLACEMENT;
    // options.labels can also rename a key-based label, matched by the
    // (normalised) key name, e.g. { password: '[PWD]' }.
    if (options.labels && options.labels[name]) return options.labels[name];
    return SENSITIVE_KEYS.get(name);
  }
  const extra = (options.sensitiveKeys || []).map(normalizeKeyName);
  if (extra.includes(name)) return options.replacement || DEFAULT_REPLACEMENT;
  return null;
}

function findSensitive(input, options = {}) {
  validateOptions(options);
  if (typeof input !== 'string') return [];
  // Same enabled / disabled logic as redact(): `only` picks the patterns
  // to look for, `except` removes patterns from that set.
  const enabled = new Set(options.only || PATTERNS.map((p) => p.name));
  const disabled = new Set(options.except || []);
  const found = [];
  for (const pattern of PATTERNS) {
    if (!enabled.has(pattern.name) || disabled.has(pattern.name)) continue;
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;
    while ((match = regex.exec(input)) !== null) {
      if (pattern.validate && !pattern.validate(match[0])) continue;
      found.push({ type: pattern.name, value: match[0], index: match.index });
      if (match[0].length === 0) regex.lastIndex++;
    }
  }
  // Custom patterns are reported as type 'custom'. Like redact(), they are
  // applied regardless of only / except — they are the caller's own patterns,
  // not one of the built-in types.
  for (const custom of options.custom || []) {
    const regex =
      custom instanceof RegExp
        ? new RegExp(custom.source, custom.flags.includes('g') ? custom.flags : custom.flags + 'g')
        : new RegExp(custom.pattern, custom.flags || 'g');
    let match;
    while ((match = regex.exec(input)) !== null) {
      found.push({ type: 'custom', value: match[0], index: match.index });
      if (match[0].length === 0) regex.lastIndex++;
    }
  }
  // Text order: sort by start position. Array.prototype.sort is stable, so
  // matches starting at the same index keep pattern order as the tie-break.
  found.sort((a, b) => a.index - b.index);
  return found;
}

module.exports = { redact, redactObject, findSensitive, PATTERNS, SENSITIVE_KEYS };


