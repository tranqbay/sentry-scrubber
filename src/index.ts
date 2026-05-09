/**
 * @tranqbay/sentry-scrubber
 *
 * PII redaction for Sentry/Glitchtip events. Walks the event before send
 * and replaces values under known PII keys with [REDACTED], replaces
 * email-shaped strings with [EMAIL].
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
  [k: string]: unknown;
};

export interface ScrubOptions {
  /** Additional regex of object key names to redact, OR'd with the default set. */
  additionalKeys?: RegExp;
  /** Set false to drop event.user entirely instead of preserving { id }. */
  preserveUserId?: boolean;
}

const DEFAULT_PII_KEYS =
  /^(email|phone|phoneNumber|firstName|first_name|lastName|last_name|fullName|full_name|name|dob|date_of_birth|birthdate|ssn|address|street|city|zip|postal|postalCode|password|token|secret|apiKey|api_key|authorization|cookie|messageBody|message_body|content|notes|symptom|diagnosis|medication|prescription|recipientEmail|recipient_email|recipientName|recipient_name)$/i;
const EMAIL_REGEX = /[\w.+-]+@[\w-]+\.[\w.-]+/g;
const REDACTED = '[REDACTED]';
const EMAIL_PLACEHOLDER = '[EMAIL]';
const MAX_DEPTH = 6;

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
    return value.replace(EMAIL_REGEX, EMAIL_PLACEHOLDER);
  }
  if (Array.isArray(value)) {
    return value.map((v) => scrubPII(v, opts, depth + 1));
  }
  if (typeof value === 'object') {
    const keys = combinePatterns(DEFAULT_PII_KEYS, opts?.additionalKeys);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = keys.test(k) ? REDACTED : scrubPII(v, opts, depth + 1);
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
      message:
        typeof b.message === 'string'
          ? b.message.replace(EMAIL_REGEX, EMAIL_PLACEHOLDER)
          : b.message,
    }));
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
