import { describe, it, expect } from 'vitest';
import {
  scrubPII,
  scrubEvent,
  phiBeforeSend,
  createPhiBeforeSend,
  type SentryEventLike,
} from './index';

describe('scrubPII', () => {
  it('redacts known PII keys at top level', () => {
    expect(
      scrubPII({ email: 'a@b.c', firstName: 'Ada', ok: 'x' }),
    ).toEqual({
      email: '[REDACTED]',
      firstName: '[REDACTED]',
      ok: 'x',
    });
  });

  it('redacts emails inside arbitrary strings', () => {
    expect(scrubPII('user a@b.c logged in')).toBe('user [EMAIL] logged in');
  });

  it('walks nested objects and arrays', () => {
    const input = {
      patient: { dob: '2000-01-01', notes: 'sensitive' },
      tags: ['ok', { phone: '+1-555' }],
    };
    expect(scrubPII(input)).toEqual({
      patient: { dob: '[REDACTED]', notes: '[REDACTED]' },
      tags: ['ok', { phone: '[REDACTED]' }],
    });
  });

  it('honors MAX_DEPTH and tolerates circular references', () => {
    const cycle: Record<string, unknown> = { a: 1 };
    cycle.self = cycle;
    expect(() => scrubPII(cycle)).not.toThrow();
  });

  it('honors additionalKeys', () => {
    expect(
      scrubPII(
        { customField: 'leak', other: 'fine' },
        { additionalKeys: /^customField$/i },
      ),
    ).toEqual({ customField: '[REDACTED]', other: 'fine' });
  });

  it('passes through non-object primitives', () => {
    expect(scrubPII(42)).toBe(42);
    expect(scrubPII(true)).toBe(true);
    expect(scrubPII(null)).toBe(null);
    expect(scrubPII(undefined)).toBe(undefined);
  });

  it('matches snake_case PII variants too', () => {
    expect(
      scrubPII({ first_name: 'Ada', date_of_birth: '2000-01-01', ok: 'x' }),
    ).toEqual({
      first_name: '[REDACTED]',
      date_of_birth: '[REDACTED]',
      ok: 'x',
    });
  });
});

describe('scrubEvent', () => {
  it('reduces event.user to id only', () => {
    const e = {
      user: { id: 42, email: 'leak@x.com', firstName: 'Ada' },
    };
    expect(scrubEvent(e).user).toEqual({ id: 42 });
  });

  it('drops event.user entirely if preserveUserId is false', () => {
    const e = { user: { id: 42, email: 'leak@x.com' } };
    expect(scrubEvent(e, { preserveUserId: false }).user).toBeUndefined();
  });

  it('redacts event.request.data and query_string', () => {
    const e = {
      request: {
        data: { email: 'a@b.c', notes: 'phi' },
        query_string: 'q=patientName',
      },
    };
    const out = scrubEvent(e);
    expect(out.request?.data).toEqual({
      email: '[REDACTED]',
      notes: '[REDACTED]',
    });
    expect(out.request?.query_string).toBe('[REDACTED]');
  });

  it('walks event.extra and event.contexts', () => {
    const e = {
      extra: { dob: '2000-01-01', okay: 1 },
      contexts: { app: { medication: 'paracetamol', version: '1.0' } },
    };
    const out = scrubEvent(e);
    expect(out.extra).toEqual({ dob: '[REDACTED]', okay: 1 });
    expect(out.contexts).toEqual({
      app: { medication: '[REDACTED]', version: '1.0' },
    });
  });

  it('scrubs breadcrumb data and email in messages', () => {
    const e = {
      breadcrumbs: [
        {
          data: { email: 'leak@x.com' },
          message: 'http GET /api',
          category: 'http',
        },
        { data: null, message: 'user a@b.c logged in', category: 'log' },
      ],
    };
    const out = scrubEvent(e);
    expect(out.breadcrumbs?.[0]?.data).toEqual({ email: '[REDACTED]' });
    expect(out.breadcrumbs?.[0]?.message).toBe('http GET /api');
    expect(out.breadcrumbs?.[1]?.data).toBeNull();
    expect(out.breadcrumbs?.[1]?.message).toBe('user [EMAIL] logged in');
  });

  it('returns non-object inputs unchanged', () => {
    expect(scrubEvent(null as unknown as SentryEventLike)).toBe(null);
  });
});

describe('phiBeforeSend', () => {
  it('is a Sentry-compatible beforeSend with the default key set', () => {
    const e = {
      user: { id: 1, email: 'leak@x.com' },
      extra: { dob: '2000-01-01', notes: 'phi' },
    };
    const out = phiBeforeSend(e);
    expect(out.user).toEqual({ id: 1 });
    expect(out.extra).toEqual({
      dob: '[REDACTED]',
      notes: '[REDACTED]',
    });
  });
});

describe('createPhiBeforeSend', () => {
  it('returns a beforeSend that respects custom keys', () => {
    const beforeSend = createPhiBeforeSend({
      additionalKeys: /^chartId$/i,
    });
    const e = { extra: { chartId: '12345', okay: 'fine' } };
    expect(beforeSend(e).extra).toEqual({
      chartId: '[REDACTED]',
      okay: 'fine',
    });
  });

  it('still applies default keys when additionalKeys is set', () => {
    const beforeSend = createPhiBeforeSend({ additionalKeys: /^foo$/i });
    expect(beforeSend({ extra: { email: 'a@b.c', foo: 'bar' } }).extra).toEqual(
      { email: '[REDACTED]', foo: '[REDACTED]' },
    );
  });
});
