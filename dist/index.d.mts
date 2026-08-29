type SentryEventLike = {
    user?: {
        id?: string | number;
        [k: string]: unknown;
    };
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
    logentry?: {
        message?: unknown;
        [k: string]: unknown;
    };
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
interface ScrubOptions {
    /** Additional regex of object key names to redact, OR'd with the default set. */
    additionalKeys?: RegExp;
}
declare function scrubPII(value: unknown, opts?: ScrubOptions, depth?: number): unknown;
declare function scrubEvent<T extends SentryEventLike>(event: T): T;
/** Drop-in beforeSend for Sentry.init using the default tranqbay PHI key set. */
declare const phiBeforeSend: <T extends SentryEventLike>(event: T) => T;
interface NoiseOptions {
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
}
/** Returns true when an event is non-actionable noise per `opts`. */
declare function isNoise(event: SentryEventLike, opts?: NoiseOptions): boolean;
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
declare function createBeforeSend(opts?: NoiseOptions): <T extends SentryEventLike>(event: T) => T | null;

export { type NoiseOptions, type ScrubOptions, type SentryEventLike, createBeforeSend, isNoise, phiBeforeSend, scrubEvent, scrubPII };
