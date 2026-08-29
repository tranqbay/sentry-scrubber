# @tranqbay/sentry-scrubber

A small, dependency-free `beforeSend` PII/PHI scrubber (and noise filter) for the Sentry / GlitchTip JavaScript SDK.

## Why

Self-hosted, Sentry-compatible error trackers (e.g. GlitchTip) don't provide the server-side data scrubbing that Sentry's hosted product does (see GlitchTip issues [#134](https://gitlab.com/glitchtip/glitchtip-backend/-/issues/134), [#251](https://gitlab.com/glitchtip/glitchtip-backend/-/issues/251), [#315](https://gitlab.com/glitchtip/glitchtip-backend/-/work_items/315)). The reliable place to remove sensitive data is therefore the SDK's `beforeSend` hook, before events ever leave the process.

This package centralises a strict allowlist so an event retains diagnostic structure without sending patient or credential fields.

## Install

In your service's `package.json`:

```json
{
  "optionalDependencies": {
    "@tranqbay/sentry-scrubber": "github:tranqbay/sentry-scrubber#v1.1.0"
  }
}
```

Use `optionalDependencies` for Node.js backends so a build where the package isn't available still succeeds (the consumer's `instrument.ts` falls back to a no-op). For frontend bundles, use `dependencies` instead, since the dep is bundled at build time and the runtime fallback isn't relevant.

## Version 1 migration

- use `phiBeforeSend` instead of `createPhiBeforeSend`
- `event.user` is always removed; `preserveUserId` no longer applies
- `scrubEvent` accepts only the event, and `createBeforeSend` accepts only noise options
- `additionalKeys` remains available only through the recursive `scrubPII` utility

The event scrubber returns the scrubbed event and also updates the supplied event
for compatibility with older wrappers. New integrations should return its result
from `beforeSend`.

Technical metadata is limited to short code-shaped values. Standard
`package@semver` release names remain supported, including prerelease and build
metadata.

## Usage (NestJS backend)

```typescript
// src/instrument.ts
(async () => {
  const Sentry = await import('@sentry/nestjs');
  const { httpIntegration } = await import('@sentry/nestjs');

  let beforeSend: ((event: unknown) => unknown) | undefined;
  try {
    ({ phiBeforeSend: beforeSend } = await import(
      '@tranqbay/sentry-scrubber'
    ));
  } catch {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        '@tranqbay/sentry-scrubber missing in production',
      );
    }
    console.warn(
      '[sentry] sentry-scrubber not installed, running without PII scrubbing',
    );
  }

  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    skipOpenTelemetrySetup: true,
    registerEsmLoaderHooks: false,
    integrations: [httpIntegration({ spans: false })],
    beforeSend,
  });
})();
```

`beforeSend: undefined` is valid Sentry config (treated as no callback), so the dev no-op path needs no extra wiring.

## Usage (Next.js frontend)

Static import, no graceful-degrade needed because the dep is bundled at build time:

```typescript
// sentry.client.config.ts
import { phiBeforeSend } from '@tranqbay/sentry-scrubber';

Sentry.init({
  // ...existing config including ignoreErrors and the existing beforeSend filters...
  beforeSend(event) {
    if (process.env.NODE_ENV === 'development') return null;
    // ...existing exception-type / extension-URL filters that return null...

    return phiBeforeSend(event);
  },
});
```

Same pattern in `sentry.server.config.ts` and `sentry.edge.config.ts`.

## What gets scrubbed

The default is strict and fail closed:

- `event.user`, `event.extra`, non-trace contexts, `event.tags`, `event.transaction`, `event.culprit`, and `event.fingerprint` are removed
- `event.request` retains only the HTTP method
- breadcrumbs retain only type, level, and timestamp
- freeform messages and exception values become `[REDACTED]`
- safe code locations, stack structure, trace IDs, and source-map debug IDs remain
- frame variables, code context, mechanism data, and unknown fields are removed
- recursive utility calls replace data beyond the depth limit with `[REDACTED]`

There is no permissive event mode in version 1.
Technical names such as exception type, logger, and release are retained for grouping. Keep them code-defined and never interpolate patient identifiers into them.

## Recursive utility

`scrubPII(value, { additionalKeys })` remains available for data that is not a Sentry event. It walks keys recursively and masks email-shaped strings.
It is not safe for arbitrary freeform clinical text. Use the strict event scrubber for Sentry data.

### Key matching

- **Exact** match for generic words (`name`, `address`, `city`, `content`, …) so lookalikes like `username`/`filename` are not over-redacted.
- **Substring** match for high-signal tokens (`email`, `password`, `secret`, `token`, `authorization`, `cookie`, `ssn`, `creditCard`, `cvv`, `phone`, `firstName`/`lastName`/`fullName`) so compound keys like `userEmail`, `patientPhone`, `csrfToken` are caught.

## Default PII key set (case-insensitive, snake_case variants matched)

`email`, `phone`, `phoneNumber`, `firstName`, `lastName`, `fullName`, `name`, `dob`, `date_of_birth`, `birthdate`, `ssn`, `address`, `street`, `city`, `zip`, `postal`, `postalCode`, `password`, `token`, `secret`, `apiKey`, `authorization`, `cookie`, `messageBody`, `content`, `notes`, `symptom`, `diagnosis`, `medication`, `prescription`, `recipientEmail`, `recipientName`.

### Custom keys

```typescript
import { scrubPII } from '@tranqbay/sentry-scrubber';

const safe = scrubPII(input, {
  additionalKeys: /^(chartId|clinicalNote)$/i,
});
```

The `additionalKeys` regex is OR'd with the default set; defaults still apply.

## Dropping noise (warnings + patterns)

Beyond PII scrubbing, the package can drop non-actionable events before they
reach GlitchTip. Use `createBeforeSend`, which drops noise (returns `null`) and
then scrubs PII on whatever survives, so a service wires in **one** callback:

```typescript
import { createBeforeSend } from '@tranqbay/sentry-scrubber';

Sentry.init({
  // ...
  beforeSend: createBeforeSend({
    dropWarnings: true,
    dropPatterns: [/broker transport failure/i, /subscription not found/i],
  }),
});
```

- **`dropWarnings`** drops events at or below `warning` severity
  (`warning`/`info`/`debug`/`log`). This enforces "warnings never reach the
  error tracker" centrally, so services don't have to hand-roll a logger that
  refrains from forwarding warnings. `error`/`fatal` pass through.
- **`dropPatterns`** drops events whose message/logentry/exception text
  matches any pattern. For known, non-actionable noise families (e.g. recurring
  third-party transport churn) a service wants suppressed at the edge.
- **`matchExceptionType`** includes exception class names in `dropPatterns`
  matching. It is disabled by default so a broad expression such as `/error/i`
  does not discard every `TypeError`.

`isNoise(event, opts)` is exported separately if you need the predicate inside
an existing `beforeSend` (e.g. a Next.js config that already returns `null` for
some cases), return `null` when it is `true`, then call `phiBeforeSend`.

## Bumping the package

1. Edit `src/index.ts`
2. `npm test`
3. `npm run build` (regenerates `dist/`)
4. Commit src + dist + bumped version in `package.json`
5. `git tag -a vX.Y.Z -m '...'` and `git push origin main --tags`
6. Bump consumers: `package.json` value to `#vX.Y.Z`, run `npm install`

## Versioning

Semver. Patch for new PII keys, minor for new exports, major for breaking changes (e.g. removing a key from the default set).

## License

UNLICENSED, internal tranqbay use only.
