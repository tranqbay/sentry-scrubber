export type SentryEventLike = {
  user?: { id?: string | number; [k: string]: unknown };
  request?: {
    method?: unknown;
    data?: unknown;
    query_string?: unknown;
    [k: string]: unknown;
  };
  extra?: Record<string, unknown>;
  contexts?: Record<string, unknown>;
  tags?: Record<string, unknown>;
  transaction?: string;
  culprit?: string;
  fingerprint?: string[];
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
    values?: Array<{
      type?: string;
      value?: string;
      stacktrace?: unknown;
      mechanism?: unknown;
      [k: string]: unknown;
    }>;
    [k: string]: unknown;
  };
  [k: string]: unknown;
};

export interface ScrubOptions {
  /** Additional regex of object key names to redact, OR'd with the default set. */
  additionalKeys?: RegExp;
}

// Exact-match key names (case-insensitive). Generic words live here so we don't
// over-redact lookalikes (e.g. "name" must not match "filename"/"username").
const DEFAULT_PII_KEYS =
  /^(email|phone|phoneNumber|firstName|first_name|lastName|last_name|fullName|full_name|name|dob|date_of_birth|birthdate|ssn|address|street|city|zip|postal|postalCode|password|token|secret|apiKey|api_key|authorization|cookie|messageBody|message_body|content|notes|symptom|diagnosis|medication|prescription|recipientEmail|recipient_email|recipientName|recipient_name)$/i;
// High-signal tokens matched as a substring, so compound keys are caught too.
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

const TECHNICAL_VALUE = /^(?=.{1,128}$)(?!.*@)(?!\d{7,}$)[A-Za-z0-9_.:/<>()#$-]+$/;
const PACKAGE_RELEASE = /^(?=.{1,128}$)(?:@[A-Za-z0-9_.-]+\/)?[A-Za-z0-9_.-]+@v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$/;
const CODE_LOCATION = /\.(?:c|cc|cpp|cs|go|java|js|jsx|kt|mjs|cjs|php|py|rb|rs|swift|ts|tsx)(?::\d+)?$/i;
const TRACE_ID = /^[a-f0-9]{16,32}$/i;

function technicalString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const scrubbed = scrubString(value);
  return TECHNICAL_VALUE.test(scrubbed) ? scrubbed : undefined;
}

function releaseString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  return technicalString(value) ?? (PACKAGE_RELEASE.test(value) ? value : undefined);
}

function codeLocation(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const scrubbed = scrubString(value).split(/[?#]/, 1)[0].slice(0, 512);
  return CODE_LOCATION.test(scrubbed) ? scrubbed : undefined;
}

function copyTechnical(
  source: Record<string, unknown>,
  fields: string[],
): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const field of fields) {
    const value = technicalString(source[field]);
    if (value !== undefined) output[field] = value;
  }
  return output;
}

function strictEvent(event: SentryEventLike): SentryEventLike {
  const safe = copyTechnical(event, [
    'platform',
    'environment',
    'dist',
    'logger',
    'server_name',
  ]) as SentryEventLike;
  const release = releaseString(event.release);
  if (release) safe.release = release;

  if (typeof event.event_id === 'string' && /^[a-f0-9]{32}$/i.test(event.event_id)) {
    safe.event_id = event.event_id;
  }
  if (
    typeof event.level === 'string' &&
    ['fatal', 'error', 'warning', 'info', 'debug', 'log'].includes(
      event.level.toLowerCase(),
    )
  ) {
    safe.level = event.level.toLowerCase();
  }
  if (
    typeof event.timestamp === 'number' ||
    (typeof event.timestamp === 'string' &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(event.timestamp))
  ) {
    safe.timestamp = event.timestamp;
  }

  if (
    event.request &&
    typeof event.request.method === 'string' &&
    /^[A-Z]{3,10}$/.test(event.request.method)
  ) {
    safe.request = { method: event.request.method };
  }

  if (event.breadcrumbs) {
    safe.breadcrumbs = event.breadcrumbs.map((breadcrumb) => {
      const output: Record<string, unknown> = {};
      const type = technicalString(breadcrumb.type);
      const level = technicalString(breadcrumb.level);
      if (type) output.type = type;
      if (level) output.level = level;
      if (typeof breadcrumb.timestamp === 'number') {
        output.timestamp = breadcrumb.timestamp;
      }
      return output;
    });
  }

  if (event.message !== undefined) safe.message = REDACTED;
  if (event.logentry !== undefined) safe.logentry = { message: REDACTED };

  if (event.exception?.values) {
    safe.exception = {
      values: event.exception.values.map((exception) => {
        const output = copyTechnical(exception, [
          'type',
          'module',
        ]);
        if (
          typeof exception.thread_id === 'number' ||
          (typeof exception.thread_id === 'string' &&
            /^[a-f0-9-]{1,64}$/i.test(exception.thread_id))
        ) {
          output.thread_id = exception.thread_id;
        }
        if (exception.value !== undefined) output.value = REDACTED;

        const stacktrace = exception.stacktrace as
          | { frames?: Array<Record<string, unknown>> }
          | undefined;
        if (stacktrace?.frames) {
          output.stacktrace = {
            frames: stacktrace.frames.map((frame) => {
              const safeFrame = copyTechnical(frame, [
                'function',
                'module',
                'instruction_addr',
                'package',
                'platform',
              ]);
              for (const field of ['filename', 'abs_path']) {
                const value = codeLocation(frame[field]);
                if (value) safeFrame[field] = value;
              }
              for (const field of ['lineno', 'colno']) {
                if (typeof frame[field] === 'number') {
                  safeFrame[field] = frame[field];
                }
              }
              if (typeof frame.in_app === 'boolean') {
                safeFrame.in_app = frame.in_app;
              }
              return safeFrame;
            }),
          };
        }

        const mechanism = exception.mechanism as
          | Record<string, unknown>
          | undefined;
        if (mechanism) {
          const safeMechanism = copyTechnical(mechanism, [
            'type',
            'exception_id',
            'parent_id',
          ]);
          for (const field of ['handled', 'synthetic']) {
            if (typeof mechanism[field] === 'boolean') {
              safeMechanism[field] = mechanism[field];
            }
          }
          output.mechanism = safeMechanism;
        }

        return output;
      }),
    };
  }

  const trace = (event.contexts as Record<string, unknown> | undefined)?.trace;
  if (trace && typeof trace === 'object') {
    const source = trace as Record<string, unknown>;
    const safeTrace = copyTechnical(source, ['op', 'status', 'origin']);
    for (const field of ['trace_id', 'span_id', 'parent_span_id']) {
      if (typeof source[field] === 'string' && TRACE_ID.test(source[field])) {
        safeTrace[field] = source[field];
      }
    }
    safe.contexts = { trace: safeTrace };
  }

  const debugMeta = event.debug_meta as
    | { images?: Array<Record<string, unknown>> }
    | undefined;
  if (debugMeta?.images) {
    safe.debug_meta = {
      images: debugMeta.images.map((image) => {
        const output = copyTechnical(image, [
          'type',
          'debug_id',
          'code_id',
          'image_addr',
          'image_size',
          'arch',
        ]);
        for (const field of ['code_file', 'debug_file']) {
          const value = codeLocation(image[field]);
          if (value) output[field] = value;
        }
        return output;
      }),
    };
  }

  return safe;
}

export function scrubPII(
  value: unknown,
  opts?: ScrubOptions,
  depth = 0,
): unknown {
  if (depth > MAX_DEPTH) return REDACTED;
  if (value == null) return value;
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

export function scrubEvent<T extends object>(event: T): T {
  if (!event || typeof event !== 'object') return event;
  const safe = strictEvent(event as unknown as SentryEventLike) as unknown as T;
  const target = event as unknown as Record<string, unknown>;
  const safeRecord = safe as unknown as Record<string, unknown>;
  try {
    for (const key of Object.keys(target)) delete target[key];
    Object.assign(target, safe);
    const safeKeys = Object.keys(safe);
    if (
      Object.keys(target).length !== safeKeys.length ||
      safeKeys.some((key) => target[key] !== safeRecord[key])
    ) {
      return safe;
    }
    return event;
  } catch {
    return safe;
  }
}

/** Drop-in beforeSend for Sentry.init using the default tranqbay PHI key set. */
export const phiBeforeSend = <T extends object>(event: T): T =>
  scrubEvent(event);

export interface NoiseOptions {
  /**
   * Drop events at or below `warning` severity (warning/info/debug/log).
   * Warnings are operational signals, not errors. Forwarding them to error
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
  matchExceptionType?: boolean;
}

const NOISE_LEVELS = new Set(['warning', 'info', 'debug', 'log']);

/** Collects the text-bearing fields of an event for pattern matching. */
function eventText(event: SentryEventLike, matchExceptionType = false): string {
  const parts: string[] = [];
  if (typeof event.message === 'string') parts.push(event.message);
  if (event.logentry && typeof event.logentry.message === 'string') {
    parts.push(event.logentry.message);
  }
  for (const ex of event.exception?.values ?? []) {
    if (matchExceptionType && ex.type) parts.push(ex.type);
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
    const text = eventText(event, opts.matchExceptionType);
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
export function createBeforeSend(opts?: NoiseOptions) {
  return <T extends object>(event: T): T | null => {
    if (isNoise(event as unknown as SentryEventLike, opts)) return null;
    return scrubEvent(event);
  };
}
