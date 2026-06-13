// src/index.ts
var DEFAULT_PII_KEYS = /^(email|phone|phoneNumber|firstName|first_name|lastName|last_name|fullName|full_name|name|dob|date_of_birth|birthdate|ssn|address|street|city|zip|postal|postalCode|password|token|secret|apiKey|api_key|authorization|cookie|messageBody|message_body|content|notes|symptom|diagnosis|medication|prescription|recipientEmail|recipient_email|recipientName|recipient_name)$/i;
var EMAIL_REGEX = /[\w.+-]+@[\w-]+\.[\w.-]+/g;
var REDACTED = "[REDACTED]";
var EMAIL_PLACEHOLDER = "[EMAIL]";
var MAX_DEPTH = 6;
function combinePatterns(base, additional) {
  if (!additional) return base;
  return new RegExp(
    `(?:${base.source})|(?:${additional.source})`,
    base.flags
  );
}
function scrubPII(value, opts, depth = 0) {
  if (depth > MAX_DEPTH || value == null) return value;
  if (typeof value === "string") {
    return value.replace(EMAIL_REGEX, EMAIL_PLACEHOLDER);
  }
  if (Array.isArray(value)) {
    return value.map((v) => scrubPII(v, opts, depth + 1));
  }
  if (typeof value === "object") {
    const keys = combinePatterns(DEFAULT_PII_KEYS, opts?.additionalKeys);
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = keys.test(k) ? REDACTED : scrubPII(v, opts, depth + 1);
    }
    return out;
  }
  return value;
}
function scrubEvent(event, opts) {
  if (!event || typeof event !== "object") return event;
  if (event.user) {
    if (opts?.preserveUserId === false) {
      delete event.user;
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
    event.extra = scrubPII(event.extra, opts);
  }
  if (event.contexts) {
    event.contexts = scrubPII(event.contexts, opts);
  }
  if (event.breadcrumbs && Array.isArray(event.breadcrumbs)) {
    event.breadcrumbs = event.breadcrumbs.map((b) => ({
      ...b,
      data: b.data ? scrubPII(b.data, opts) : b.data,
      message: typeof b.message === "string" ? b.message.replace(EMAIL_REGEX, EMAIL_PLACEHOLDER) : b.message
    }));
  }
  return event;
}
var phiBeforeSend = (event) => scrubEvent(event);
function createPhiBeforeSend(opts) {
  return (event) => scrubEvent(event, opts);
}
var NOISE_LEVELS = /* @__PURE__ */ new Set(["warning", "info", "debug", "log"]);
function eventText(event) {
  const parts = [];
  if (typeof event.message === "string") parts.push(event.message);
  if (event.logentry && typeof event.logentry.message === "string") {
    parts.push(event.logentry.message);
  }
  for (const ex of event.exception?.values ?? []) {
    if (ex.type) parts.push(ex.type);
    if (ex.value) parts.push(ex.value);
  }
  return parts.join("\n");
}
function isNoise(event, opts) {
  if (!event || typeof event !== "object" || !opts) return false;
  if (opts.dropWarnings && typeof event.level === "string" && NOISE_LEVELS.has(event.level.toLowerCase())) {
    return true;
  }
  if (opts.dropPatterns?.length) {
    const text = eventText(event);
    if (text && opts.dropPatterns.some((re) => re.test(text))) return true;
  }
  return false;
}
function createBeforeSend(opts) {
  return (event) => {
    if (isNoise(event, opts)) return null;
    return scrubEvent(event, opts);
  };
}
export {
  createBeforeSend,
  createPhiBeforeSend,
  isNoise,
  phiBeforeSend,
  scrubEvent,
  scrubPII
};
