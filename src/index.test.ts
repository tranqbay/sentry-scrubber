import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  createBeforeSend,
  isNoise,
  normalizeRoute,
  phiBeforeSend,
  scrubEvent,
  scrubPII,
  type SentryEventLike,
} from './index';

describe('scrubPII', () => {
  it('redacts sensitive keys and emails', () => {
    expect(
      scrubPII({
        email: 'person@example.com',
        firstName: 'Ada',
        okay: 'contact person@example.com',
      }),
    ).toEqual({
      email: '[REDACTED]',
      firstName: '[REDACTED]',
      okay: 'contact [EMAIL]',
    });
  });

  it('walks nested objects and arrays', () => {
    expect(
      scrubPII({
        patient: { dob: '2000-01-01', notes: 'sensitive' },
        values: [{ patientPhone: '+1-555' }],
      }),
    ).toEqual({
      patient: { dob: '[REDACTED]', notes: '[REDACTED]' },
      values: [{ patientPhone: '[REDACTED]' }],
    });
  });

  it('redacts circular and over-depth data', () => {
    const cycle: Record<string, unknown> = { value: 1 };
    cycle.self = cycle;
    const circularOutput = JSON.stringify(scrubPII(cycle));
    expect(circularOutput).toContain('[REDACTED]');

    const deep = {
      one: {
        two: {
          three: {
            four: { five: { six: { seven: 'deep PHI' } } },
          },
        },
      },
    };
    expect(JSON.stringify(scrubPII(deep))).not.toContain('deep PHI');
  });

  it('honors additional keys', () => {
    expect(
      scrubPII(
        { chartId: 'secret', okay: 'fine' },
        { additionalKeys: /^chartId$/i },
      ),
    ).toEqual({ chartId: '[REDACTED]', okay: 'fine' });
  });

  it('passes through non-object primitives', () => {
    expect(scrubPII(42)).toBe(42);
    expect(scrubPII(true)).toBe(true);
    expect(scrubPII(null)).toBe(null);
    expect(scrubPII(undefined)).toBe(undefined);
  });
});

describe('scrubEvent', () => {
  it('keeps only allowlisted technical context', () => {
    const input: SentryEventLike = {
      event_id: '0123456789abcdef0123456789abcdef',
      platform: 'javascript',
      timestamp: '2026-08-29T04:00:00Z',
      level: 'ERROR',
      environment: 'staging',
      release: 'service@1.2.3+build.5',
      dist: '42',
      logger: 'booking.service',
      server_name: 'booking-7d9f6',
      modules: { phiPackage: 'private notes' },
      sdk: { integration: 'patient@example.com' },
      user: { id: 'patient-1', email: 'patient@example.com' },
      request: {
        method: 'POST',
        url: '/clients/patient-1?concern=trauma',
        cookies: 'session=secret',
        data: { notes: 'private notes' },
      },
      extra: { details: 'Jane Doe has trauma' },
      tags: { patient: 'Jane Doe' },
      transaction: '/clients/patient-1',
      culprit: 'patient-1',
      fingerprint: ['patient-1'],
      threads: { values: [{ name: 'Jane Doe' }] },
      sdkProcessingMetadata: { requestBody: 'private notes' },
      message: 'Jane Doe could not book therapy',
      logentry: { message: 'Call patient on +44 1234', params: ['Jane Doe'] },
      breadcrumbs: [
        {
          type: 'http',
          category: 'POST /clients/patient-1',
          level: 'info',
          timestamp: 1,
          message: 'POST /clients/patient-1',
          data: { notes: 'private notes' },
        },
      ],
      contexts: {
        trace: {
          trace_id: '0123456789abcdef0123456789abcdef',
          span_id: '0123456789abcdef',
          parent_span_id: 'fedcba9876543210',
          op: 'http.server',
          status: 'internal_error',
          origin: 'auto.http.otel',
          description: 'Jane Doe',
        },
        clinical: { concern: 'trauma' },
      },
      exception: {
        values: [
          {
            type: 'BookingError',
            module: 'booking.service',
            thread_id: 3,
            value: 'Jane Doe has trauma',
            stacktrace: {
              frames: [
                {
                  filename:
                    'https://tranq.online/_next/static/chunks/booking.js?email=patient@example.com',
                  abs_path:
                    '/app/src/booking.ts?patient=patient-1',
                  function: 'createBooking',
                  module: 'booking.service',
                  lineno: 42,
                  colno: 7,
                  in_app: true,
                  vars: { patientName: 'Jane Doe' },
                  context_line: 'throw new Error(patientName)',
                },
              ],
            },
            mechanism: {
              type: 'generic',
              handled: false,
              synthetic: true,
              data: { requestBody: 'private notes' },
            },
          },
        ],
      },
      debug_meta: {
        images: [
          {
            type: 'sourcemap',
            debug_id: '01234567-89ab-cdef-0123-456789abcdef',
            code_file:
              'https://tranq.online/_next/static/chunks/booking.js?email=patient@example.com',
            secretData: 'private notes',
          },
        ],
      },
    };

    const output = scrubEvent(input);

    expect(output).toBe(input);
    expect(output).toMatchObject({
      event_id: '0123456789abcdef0123456789abcdef',
      platform: 'javascript',
      timestamp: '2026-08-29T04:00:00Z',
      level: 'error',
      environment: 'staging',
      release: 'service@1.2.3+build.5',
      dist: '42',
      logger: 'booking.service',
      server_name: 'booking-7d9f6',
      request: { method: 'POST' },
      message: '[REDACTED]',
      logentry: { message: '[REDACTED]' },
      breadcrumbs: [{ type: 'http', level: 'info', timestamp: 1 }],
    });
    expect(output.contexts).toEqual({
      trace: {
        trace_id: '0123456789abcdef0123456789abcdef',
        span_id: '0123456789abcdef',
        parent_span_id: 'fedcba9876543210',
        op: 'http.server',
        status: 'internal_error',
        origin: 'auto.http.otel',
      },
    });

    const exception = output.exception?.values?.[0];
    expect(exception).toMatchObject({
      type: 'BookingError',
      module: 'booking.service',
      thread_id: 3,
      value: '[REDACTED]',
      mechanism: { type: 'generic', handled: false, synthetic: true },
    });
    const frame = (
      exception?.stacktrace as { frames: Array<Record<string, unknown>> }
    ).frames[0];
    expect(frame).toEqual({
      filename: 'https://tranq.online/_next/static/chunks/booking.js',
      abs_path: '/app/src/booking.ts',
      function: 'createBooking',
      module: 'booking.service',
      lineno: 42,
      colno: 7,
      in_app: true,
    });
    expect(output.debug_meta).toEqual({
      images: [
        {
          type: 'sourcemap',
          debug_id: '01234567-89ab-cdef-0123-456789abcdef',
          code_file: 'https://tranq.online/_next/static/chunks/booking.js',
        },
      ],
    });

    const serialized = JSON.stringify(output);
    for (const value of [
      'patient-1',
      'patient@example.com',
      'Jane Doe',
      'trauma',
      'private notes',
      '+44 1234',
      'session=secret',
      'phiPackage',
    ]) {
      expect(serialized).not.toContain(value);
    }
    expect(input.user).toBeUndefined();
  });

  it('drops malformed technical values', () => {
    expect(
      scrubEvent({
        event_id: 'person@example.com',
        environment: 'patient@example.com',
        release: 'patient@localhost',
        logger: '447700900123',
        server_name: '+447700900123',
        level: 'patient',
        timestamp: 'not-a-time',
        request: { method: 'patient-name' },
      }),
    ).toEqual({});
  });

  it('returns non-object inputs unchanged', () => {
    expect(scrubEvent(null as unknown as SentryEventLike)).toBe(null);
  });

  it('returns a safe copy when the event cannot be updated', () => {
    const event = Object.freeze({
      level: 'error',
      user: { id: 'patient-1' },
      message: 'patient@example.com',
    });
    const output = scrubEvent(event);
    expect(output).not.toBe(event);
    expect(output).toEqual({ level: 'error', message: '[REDACTED]' });
  });
});

describe('phiBeforeSend', () => {
  it('uses the strict allowlist', () => {
    const event = {
      level: 'error',
      user: { id: 'patient-1' },
      message: 'patient@example.com',
    };
    expect(phiBeforeSend(event)).toBe(event);
    expect(event).toEqual({ level: 'error', message: '[REDACTED]' });
  });

  it('preserves an SDK event type without index signatures', () => {
    interface SdkEvent {
      type: 'error';
      request?: { method?: string; data?: unknown };
      breadcrumbs?: Array<{ message?: string; data?: unknown }>;
    }

    const event: SdkEvent = {
      type: 'error',
      request: { method: 'POST', data: { notes: 'private' } },
      breadcrumbs: [{ message: 'patient@example.com' }],
    };
    const output = phiBeforeSend(event);

    expectTypeOf(output).toEqualTypeOf<SdkEvent>();
    expect(output).toBe(event);
  });
});

describe('noise filtering', () => {
  it('drops warning and lower levels when configured', () => {
    const options = { dropWarnings: true };
    expect(isNoise({ level: 'warning' }, options)).toBe(true);
    expect(isNoise({ level: 'info' }, options)).toBe(true);
    expect(isNoise({ level: 'error' }, options)).toBe(false);
  });

  it('matches configured message patterns', () => {
    const options = { dropPatterns: [/broker transport failure/i] };
    expect(
      isNoise(
        { level: 'error', message: 'Broker transport failure' },
        options,
      ),
    ).toBe(true);
    expect(isNoise({ level: 'error', message: 'Database failed' }, options)).toBe(
      false,
    );
  });

  it('matches exception values but not exception types', () => {
    const options = { dropPatterns: [/error/i] };
    expect(
      isNoise(
        { exception: { values: [{ type: 'TypeError', value: 'Database failed' }] } },
        options,
      ),
    ).toBe(false);
    expect(
      isNoise(
        { exception: { values: [{ type: 'TypeError', value: 'Expected error' }] } },
        options,
      ),
    ).toBe(true);
    expect(
      isNoise(
        { exception: { values: [{ type: 'TypeError', value: 'Database failed' }] } },
        { dropPatterns: [/TypeError/], matchExceptionType: true },
      ),
    ).toBe(true);
  });

  it('resets stateful regular expressions', () => {
    const pattern = /expected noise/gi;
    expect(isNoise({ message: 'expected noise' }, { dropPatterns: [pattern] })).toBe(
      true,
    );
    expect(isNoise({ message: 'expected noise' }, { dropPatterns: [pattern] })).toBe(
      true,
    );
  });
});

describe('createBeforeSend', () => {
  it('drops noise before scrubbing', () => {
    const beforeSend = createBeforeSend({ dropWarnings: true });
    expect(beforeSend({ level: 'warning', message: 'noise' })).toBeNull();
  });

  it('strictly scrubs retained errors', () => {
    const beforeSend = createBeforeSend({ dropWarnings: true });
    expect(
      beforeSend({
        level: 'error',
        user: { id: 'patient-1' },
        message: 'patient@example.com',
      }),
    ).toEqual({ level: 'error', message: '[REDACTED]' });
  });
});

describe('normalizeRoute', () => {
  const words = ['booking', 'metrics', 'region', 'cities', 'providers', 'best-match', 'v2', 'query'];

  it('keeps allowlisted words and replaces everything else', () => {
    expect(normalizeRoute('/booking/metrics', words)).toBe('/booking/metrics');
    expect(normalizeRoute('/region/cities/01ARZ3NDEKTSV4RRFFQ69G5FAV', words)).toBe('/region/cities/:param');
    expect(normalizeRoute('/providers/jane-doe', words)).toBe('/providers/:param');
    expect(normalizeRoute('/query/v2/providers/best-match', words)).toBe('/query/v2/providers/best-match');
    expect(normalizeRoute('/providers/123/booking', words)).toBe('/providers/:param/booking');
  });

  it('strips scheme, host, query and fragment', () => {
    expect(
      normalizeRoute('https://api.example.test/booking/metrics?email=a@b.co#x', words),
    ).toBe('/booking/metrics');
    expect(normalizeRoute('booking?concern=trauma', words)).toBe('/booking');
  });

  it('fails closed without an allowlist', () => {
    expect(normalizeRoute('/booking/metrics')).toBe('/:param/:param');
    expect(normalizeRoute('/', words)).toBe('/');
    expect(normalizeRoute('', words)).toBe('/');
  });

  it('does not let uppercase or encoded text through', () => {
    expect(normalizeRoute('/Booking/Jane%20Doe', words)).toBe('/:param/:param');
  });
});

describe('safe technical context', () => {
  const opts = {
    allowedHosts: ['api.example.test'],
    routeWords: ['booking', 'metrics', 'providers', 'categories', 'concerns'],
  };
  const secrets = [
    'jane',
    'Jane Doe',
    'patient@example.com',
    '+447700900123',
    '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    'concern=trauma',
    'trauma',
    'evil.example.test',
    'https://',
  ];
  const expectNoSecrets = (output: unknown) => {
    const serialized = JSON.stringify(output);
    for (const value of secrets) expect(serialized).not.toContain(value);
  };

  it('keeps validated technical tags and drops the rest', () => {
    const output = scrubEvent(
      {
        tags: {
          'http.method': 'GET',
          'http.status_code': '524',
          'error.code': 'ERR_BAD_RESPONSE',
          'http.route': '/booking/metrics',
          runtime: 'ssr',
          'http.host': 'api.example.test',
          patient: 'Jane Doe',
          url: 'https://api.example.test/providers/jane?concern=trauma',
        },
      },
      opts,
    );
    expect(output.tags).toEqual({
      'http.method': 'GET',
      'http.status_code': '524',
      'error.code': 'ERR_BAD_RESPONSE',
      'http.route': '/booking/metrics',
      runtime: 'ssr',
      'http.host': 'api.example.test',
    });
  });

  it('re-normalizes routes and rejects bad tag values', () => {
    const output = scrubEvent(
      {
        tags: {
          'http.method': 'get me',
          'http.status_code': '52',
          'error.code': 'JANE',
          'http.route': 'https://evil.example.test/providers/jane?concern=trauma',
          runtime: 'Jane Doe',
          'http.host': 'evil.example.test',
        },
      },
      opts,
    );
    expect(output.tags).toEqual({ 'http.route': '/providers/:param' });
    expectNoSecrets(output);
  });

  it('drops every tag when no options are given except fixed-shape ones', () => {
    const output = scrubEvent({
      tags: {
        'http.status_code': 404,
        'http.route': '/booking/jane',
        'http.host': 'api.example.test',
      },
    });
    expect(output.tags).toEqual({
      'http.status_code': '404',
      'http.route': '/:param/:param',
    });
  });

  it('keeps only whole-string safe messages', () => {
    const safe = [
      ['Request failed with status code 524', 'Request failed with status code 524'],
      ['Network Error', 'Network Error'],
      ['timeout of 1500ms exceeded', 'timeout of 1500ms exceeded'],
      ['canceled', 'canceled'],
      ['Failed to fetch', 'Failed to fetch'],
      ['Load failed', 'Load failed'],
      ['Loading chunk 123 failed.', 'Loading chunk 123 failed.'],
      [
        'Minified React error #418; visit https://react.dev/errors/418?args[]=Jane for the full message',
        'Minified React error #418',
      ],
      [
        "Hydration failed because the server rendered HTML didn't match the client. Jane Doe",
        "Hydration failed because the server rendered HTML didn't match the client.",
      ],
    ];
    for (const [input, expected] of safe) {
      const output = scrubEvent({
        message: input,
        exception: { values: [{ type: 'Error', value: input }] },
      });
      expect(output.message).toBe(expected);
      expect(output.exception?.values?.[0].value).toBe(expected);
    }
  });

  it('redacts messages that only look safe', () => {
    for (const input of [
      'Request failed with status code 524 for patient@example.com',
      'Network Error: jane',
      'timeout of 1500ms exceeded on /providers/jane',
      'Loading chunk jane failed. (error: https://evil.example.test/x.js)',
      'Patient Jane Doe could not book',
      'Request failed with status code 5241',
    ]) {
      const output = scrubEvent({
        message: input,
        exception: { values: [{ type: 'AxiosError', value: input }] },
      });
      expect(output.message).toBe('[REDACTED]');
      expect(output.exception?.values?.[0].value).toBe('[REDACTED]');
    }
  });

  it('keeps a fingerprint made only of already-safe values', () => {
    const output = scrubEvent(
      {
        tags: { runtime: 'ssr', 'http.route': '/booking/metrics', 'http.status_code': '524' },
        exception: { values: [{ type: 'AxiosError', value: 'x' }] },
        fingerprint: ['AxiosError', 'ssr', '/booking/metrics', '524'],
      },
      opts,
    );
    expect(output.fingerprint).toEqual(['AxiosError', 'ssr', '/booking/metrics', '524']);
  });

  it('drops a fingerprint with any unvalidated element', () => {
    for (const fingerprint of [
      ['AxiosError', 'jane'],
      ['AxiosError', '/providers/jane'],
      ['{{ default }}', '01ARZ3NDEKTSV4RRFFQ69G5FAV'],
    ]) {
      const output = scrubEvent(
        {
          tags: { runtime: 'ssr' },
          exception: { values: [{ type: 'AxiosError', value: 'x' }] },
          fingerprint,
        },
        opts,
      );
      expect(output.fingerprint).toBeUndefined();
    }
    const kept = scrubEvent({ fingerprint: ['{{ default }}'] });
    expect(kept.fingerprint).toEqual(['{{ default }}']);
  });

  it('keeps request breadcrumb method, status and normalized route only', () => {
    const output = scrubEvent(
      {
        breadcrumbs: [
          {
            type: 'http',
            category: 'xhr',
            level: 'error',
            timestamp: 1,
            message: 'GET https://api.example.test/providers/jane',
            data: {
              method: 'GET',
              status_code: 404,
              url: 'https://api.example.test/providers/jane?concern=trauma',
              route: '/providers/jane',
              body: 'patient@example.com',
            },
          },
          {
            category: 'navigation',
            timestamp: 2,
            data: { from: '/providers/jane', to: '/booking', route: '/booking' },
          },
          {
            category: 'console',
            message: 'Jane Doe',
            data: { arguments: ['Jane Doe'] },
          },
          { category: '/providers/jane', message: 'x' },
        ],
      },
      opts,
    );
    expect(output.breadcrumbs).toEqual([
      {
        type: 'http',
        category: 'xhr',
        level: 'error',
        timestamp: 1,
        data: { method: 'GET', status_code: 404, route: '/providers/:param' },
      },
      { category: 'navigation', timestamp: 2, data: { route: '/booking' } },
      { category: 'console' },
      {},
    ]);
    expectNoSecrets(output);
  });

  it('passes options through createBeforeSend', () => {
    const beforeSend = createBeforeSend({ dropWarnings: true, ...opts });
    const output = beforeSend({
      level: 'error',
      tags: { 'http.host': 'api.example.test', 'http.route': '/booking/jane' },
    });
    expect(output).toEqual({
      level: 'error',
      tags: { 'http.host': 'api.example.test', 'http.route': '/booking/:param' },
    });
  });
});
