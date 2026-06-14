/**
 * @tranqbay/sentry-scrubber
 *
 * PII redaction for Sentry/Glitchtip events. Walks the event before send and
 * replaces values under sensitive keys with [REDACTED] and email-shaped strings
 * with [EMAIL] — across user, request data/query/headers, extra, contexts,
 * breadcrumbs, AND the freeform error text (message, logentry, exception
 * values) where PII most often leaks.
 *
 * Two consumption modes:
 *  - phiBeforeSend: drop-in default for Sentry.init({ beforeSend: ... })
 *  - createPhiBeforeSend({ additionalKeys }): factory for service-specific keys
 */

export type SentryEventLike = {
  user?: { id?: string | number; [k: string]: unknown };
  request?: { data?: unknown; query_string?: unknown; [k: string]: unknown };
  extra?: Record<string, unknown>;
  contexts?: Record<string, unknown>;
  breadcrumbs?: Array<{
    data?: unknown;
    message?: unknown;
    [k: string]: unknown;
  }>;
  /** Severity: 'fatal' | 'error' | 'warning' | 'info' | 'debug' | 'log'. */
  level?: string;
  message?: unknown;
  logentry?: { message?: unknown; [k: string]: unknown };
  exception?: {
    values?: Array<{ type?: string; value?: string; [k: string]: unknown }>;
    [k: string]: unknown;
  };
  [k: string]: unknown;
};

export interface ScrubOptions {
  /** Additional regex of object key names to redact, OR'd with the default set. */
  additionalKeys?: RegExp;
  /** Set false to drop event.user entirely instead of preserving { id }. */
  preserveUserId?: boolean;
}

// Exact-match key names (case-insensitive). Generic words live here so we don't
// over-redact lookalikes (e.g. "name" must not match "filename"/"username").
const DEFAULT_PII_KEYS =
  /^(email|phone|phoneNumber|firstName|first_name|lastName|last_name|fullName|full_name|name|dob|date_of_birth|birthdate|ssn|address|street|city|zip|postal|postalCode|password|token|secret|apiKey|api_key|authorization|cookie|messageBody|message_body|content|notes|symptom|diagnosis|medication|prescription|recipientEmail|recipient_email|recipientName|recipient_name)$/i;
// High-signal tokens matched as a SUBSTRING, so compound keys are caught too —
// e.g. userEmail, patientPhone, csrfToken, billingSsn. Deliberately omits
// generic words like "name"/"address"/"content" to avoid over-redaction.
const SENSITIVE_KEY_TOKENS =
  /(email|password|passwd|secret|token|apikey|api_key|authorization|auth_token|accesstoken|access_token|refreshtoken|cookie|ssn|creditcard|credit_card|cardnumber|card_number|cvv|cvc|phone|firstname|lastname|fullname)/i;
const EMAIL_REGEX = /[\w.+-]+@[\w-]+\.[\w.-]+/g;
const REDACTED = '[REDACTED]';
const EMAIL_PLACEHOLDER = '[EMAIL]';
const MAX_DEPTH = 6;

/** Redact email-shaped substrings from a freeform string. */
function scrubString(value: string): string {
  return value.replace(EMAIL_REGEX, EMAIL_PLACEHOLDER);
}

/** True if an object key name denotes sensitive data (exact or token match). */
function isSensitiveKey(key: string, combinedExact: RegExp): boolean {
  return combinedExact.test(key) || SENSITIVE_KEY_TOKENS.test(key);
}

function combinePatterns(base: RegExp, additional?: RegExp): RegExp {
  if (!additional) return base;
  return new RegExp(
    `(?:${base.source})|(?:${additional.source})`,
    base.flags,
  );
}

export function scrubPII(
  value: unknown,
  opts?: ScrubOptions,
  depth = 0,
): unknown {
  if (depth > MAX_DEPTH || value == null) return value;
  if (typeof value === 'string') {
    return scrubString(value);
  }
  if (Array.isArray(value)) {
    return value.map((v) => scrubPII(v, opts, depth + 1));
  }
  if (typeof value === 'object') {
    const keys = combinePatterns(DEFAULT_PII_KEYS, opts?.additionalKeys);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = isSensitiveKey(k, keys) ? REDACTED : scrubPII(v, opts, depth + 1);
    }
    return out;
  }
  return value;
}

export function scrubEvent<T extends SentryEventLike>(
  event: T,
  opts?: ScrubOptions,
): T {
  if (!event || typeof event !== 'object') return event;

  if (event.user) {
    if (opts?.preserveUserId === false) {
      delete (event as SentryEventLike).user;
    } else {
      event.user = { id: event.user.id };
    }
  }
  if (event.request?.data) {
    event.request.data = scrubPII(event.request.data, opts);
  }
  if (event.request?.query_string) {
    event.request.query_string = REDACTED;
  }
  // Headers can carry cookie / authorization — walk them so the key match
  // (cookie/authorization/token) redacts and emails in values are masked.
  if (event.request && (event.request as { headers?: unknown }).headers) {
    (event.request as { headers?: unknown }).headers = scrubPII(
      (event.request as { headers?: unknown }).headers,
      opts,
    );
  }
  if (event.extra) {
    event.extra = scrubPII(event.extra, opts) as Record<string, unknown>;
  }
  if (event.contexts) {
    event.contexts = scrubPII(event.contexts, opts) as Record<string, unknown>;
  }
  if (event.breadcrumbs && Array.isArray(event.breadcrumbs)) {
    event.breadcrumbs = event.breadcrumbs.map((b) => ({
      ...b,
      data: b.data ? scrubPII(b.data, opts) : b.data,
      message: typeof b.message === 'string' ? scrubString(b.message) : b.message,
    }));
  }
  // The most common PII leak: freeform error text. Scrub the top-level message,
  // the structured logentry message, and every exception value.
  if (typeof event.message === 'string') {
    event.message = scrubString(event.message);
  }
  if (event.logentry && typeof event.logentry.message === 'string') {
    event.logentry.message = scrubString(event.logentry.message);
  }
  if (event.exception?.values) {
    for (const ex of event.exception.values) {
      if (typeof ex.value === 'string') {
        ex.value = scrubString(ex.value);
      }
    }
  }
  return event;
}

/** Drop-in beforeSend for Sentry.init using the default tranqbay PHI key set. */
export const phiBeforeSend = <T extends SentryEventLike>(event: T): T =>
  scrubEvent(event);

/** Factory for service-specific scrubbers. */
export function createPhiBeforeSend(opts: ScrubOptions) {
  return <T extends SentryEventLike>(event: T): T => scrubEvent(event, opts);
}

export interface NoiseOptions {
  /**
   * Drop events at or below `warning` severity (warning/info/debug/log).
   * Warnings are operational signals, not errors — forwarding them to error
   * tracking (e.g. via a logger that captures every warn) generates large
   * volumes of non-actionable issues. Enable this to enforce "warnings never
   * reach GlitchTip" centrally, regardless of how each service logs.
   */
  dropWarnings?: boolean;
  /**
   * Drop events whose message/logentry/exception text matches any of these
   * patterns. For known-noise families a service wants suppressed at the edge
   * (e.g. expected third-party transport churn).
   */
  dropPatterns?: RegExp[];
}

const NOISE_LEVELS = new Set(['warning', 'info', 'debug', 'log']);

/** Collects the text-bearing fields of an event for pattern matching. */
function eventText(event: SentryEventLike): string {
  const parts: string[] = [];
  if (typeof event.message === 'string') parts.push(event.message);
  if (event.logentry && typeof event.logentry.message === 'string') {
    parts.push(event.logentry.message);
  }
  for (const ex of event.exception?.values ?? []) {
    if (ex.type) parts.push(ex.type);
    if (ex.value) parts.push(ex.value);
  }
  return parts.join('\n');
}

/** Returns true when an event is non-actionable noise per `opts`. */
export function isNoise(event: SentryEventLike, opts?: NoiseOptions): boolean {
  if (!event || typeof event !== 'object' || !opts) return false;
  if (
    opts.dropWarnings &&
    typeof event.level === 'string' &&
    NOISE_LEVELS.has(event.level.toLowerCase())
  ) {
    return true;
  }
  if (opts.dropPatterns?.length) {
    const text = eventText(event);
    if (
      text &&
      opts.dropPatterns.some((re) => {
        // Reset lastIndex so a caller-supplied /g regex doesn't intermittently
        // miss across calls (stateful .test()).
        re.lastIndex = 0;
        return re.test(text);
      })
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Composed beforeSend for Sentry.init: drops non-actionable noise (returns
 * `null`, which tells Sentry to discard the event) and then scrubs PII from
 * everything that survives. A single building block so every service gets
 * consistent noise-filtering + PII redaction and can't regress by hand-rolling
 * its own logger/filter.
 *
 *   Sentry.init({
 *     beforeSend: createBeforeSend({ dropWarnings: true }),
 *   });
 */
export function createBeforeSend(opts?: ScrubOptions & NoiseOptions) {
  return <T extends SentryEventLike>(event: T): T | null => {
    if (isNoise(event, opts)) return null;
    return scrubEvent(event, opts);
  };
}
