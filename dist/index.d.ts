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

export { type ScrubOptions, type SentryEventLike, createPhiBeforeSend, phiBeforeSend, scrubEvent, scrubPII };
