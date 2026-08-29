import { describe, expect, it } from 'vitest';
import {
  createBeforeSend,
  isNoise,
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
      release: 'service-v1.2.3',
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

    expect(output).not.toBe(input);
    expect(output).toMatchObject({
      event_id: '0123456789abcdef0123456789abcdef',
      platform: 'javascript',
      timestamp: '2026-08-29T04:00:00Z',
      level: 'error',
      environment: 'staging',
      release: 'service-v1.2.3',
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
    expect(input.user?.id).toBe('patient-1');
  });

  it('drops malformed technical values', () => {
    expect(
      scrubEvent({
        event_id: 'person@example.com',
        environment: 'patient@example.com',
        level: 'patient',
        timestamp: 'not-a-time',
        request: { method: 'patient-name' },
      }),
    ).toEqual({});
  });

  it('returns non-object inputs unchanged', () => {
    expect(scrubEvent(null as unknown as SentryEventLike)).toBe(null);
  });
});

describe('phiBeforeSend', () => {
  it('uses the strict allowlist', () => {
    expect(
      phiBeforeSend({
        level: 'error',
        user: { id: 'patient-1' },
        message: 'patient@example.com',
      }),
    ).toEqual({ level: 'error', message: '[REDACTED]' });
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
