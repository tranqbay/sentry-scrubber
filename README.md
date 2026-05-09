# @tranqbay/sentry-scrubber

Internal Sentry/Glitchtip `beforeSend` PII scrubber for tranqbay services.

## Why

Glitchtip (self-hosted Sentry-compatible error tracker at `<redacted>`) does not yet have server-side data scrubbing (tracking issues: [#134](https://gitlab.com/glitchtip/glitchtip-backend/-/issues/134), [#251](https://gitlab.com/glitchtip/glitchtip-backend/-/issues/251), [#315](https://gitlab.com/glitchtip/glitchtip-backend/-/work_items/315), all open).

This package centralises the SDK-level scrubbing logic so PHI keys and email-shaped strings are redacted before events leave each service process. One source of truth, no per-repo drift.

## Install

In a tranqbay service repo's `package.json`:

```json
{
  "optionalDependencies": {
    "@tranqbay/sentry-scrubber": "github:tranqbay/sentry-scrubber#v0.1.0"
  }
}
```

Use `optionalDependencies` for Node.js backends so a contractor without read access to this repo can still build the consumer locally (the consumer's `instrument.ts` falls back to a no-op in dev). For the frontend bundle, use `dependencies` instead since the dep is bundled at build time and the runtime fallback is not relevant.

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

- `event.user` reduced to `{ id }` only (drop entirely with `preserveUserId: false`)
- `event.request.data`, `event.extra`, `event.contexts`, `event.breadcrumbs[].data`: walked recursively, values under keys matching the PII pattern replaced with `[REDACTED]`
- All string values: emails replaced with `[EMAIL]`
- `event.request.query_string`: replaced wholesale with `[REDACTED]`

## Default PII key set (case-insensitive, snake_case variants matched)

`email`, `phone`, `phoneNumber`, `firstName`, `lastName`, `fullName`, `name`, `dob`, `date_of_birth`, `birthdate`, `ssn`, `address`, `street`, `city`, `zip`, `postal`, `postalCode`, `password`, `token`, `secret`, `apiKey`, `authorization`, `cookie`, `messageBody`, `content`, `notes`, `symptom`, `diagnosis`, `medication`, `prescription`, `recipientEmail`, `recipientName`.

## Custom keys per service

```typescript
import { createPhiBeforeSend } from '@tranqbay/sentry-scrubber';

const beforeSend = createPhiBeforeSend({
  additionalKeys: /^(chartId|clinicalNote)$/i,
});
```

The `additionalKeys` regex is OR'd with the default set; defaults still apply.

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
