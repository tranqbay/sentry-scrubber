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
type SentryEventLike = {
    user?: {
        id?: string | number;
        [k: string]: unknown;
    };
    request?: {
        data?: unknown;
        query_string?: unknown;
        [k: string]: unknown;
    };
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
    logentry?: {
        message?: unknown;
        [k: string]: unknown;
    };
    exception?: {
        values?: Array<{
            type?: string;
            value?: string;
            [k: string]: unknown;
        }>;
        [k: string]: unknown;
    };
    [k: string]: unknown;
};
interface ScrubOptions {
    /** Additional regex of object key names to redact, OR'd with the default set. */
    additionalKeys?: RegExp;
    /** Set false to drop event.user entirely instead of preserving { id }. */
    preserveUserId?: boolean;
}
declare function scrubPII(value: unknown, opts?: ScrubOptions, depth?: number): unknown;
declare function scrubEvent<T extends SentryEventLike>(event: T, opts?: ScrubOptions): T;
/** Drop-in beforeSend for Sentry.init using the default tranqbay PHI key set. */
declare const phiBeforeSend: <T extends SentryEventLike>(event: T) => T;
/** Factory for service-specific scrubbers. */
declare function createPhiBeforeSend(opts: ScrubOptions): <T extends SentryEventLike>(event: T) => T;
interface NoiseOptions {
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
declare function createBeforeSend(opts?: ScrubOptions & NoiseOptions): <T extends SentryEventLike>(event: T) => T | null;

export { type NoiseOptions, type ScrubOptions, type SentryEventLike, createBeforeSend, createPhiBeforeSend, isNoise, phiBeforeSend, scrubEvent, scrubPII };
