// src/index.ts
var DEFAULT_PII_KEYS = /^(email|phone|phoneNumber|firstName|first_name|lastName|last_name|fullName|full_name|name|dob|date_of_birth|birthdate|ssn|address|street|city|zip|postal|postalCode|password|token|secret|apiKey|api_key|authorization|cookie|messageBody|message_body|content|notes|symptom|diagnosis|medication|prescription|recipientEmail|recipient_email|recipientName|recipient_name)$/i;
var SENSITIVE_KEY_TOKENS = /(email|password|passwd|secret|token|apikey|api_key|authorization|auth_token|accesstoken|access_token|refreshtoken|cookie|ssn|creditcard|credit_card|cardnumber|card_number|cvv|cvc|phone|firstname|lastname|fullname)/i;
var EMAIL_REGEX = /[\w.+-]+@[\w-]+\.[\w.-]+/g;
var REDACTED = "[REDACTED]";
var EMAIL_PLACEHOLDER = "[EMAIL]";
var MAX_DEPTH = 6;
function scrubString(value) {
  return value.replace(EMAIL_REGEX, EMAIL_PLACEHOLDER);
}
function isSensitiveKey(key, combinedExact) {
  return combinedExact.test(key) || SENSITIVE_KEY_TOKENS.test(key);
}
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
    return scrubString(value);
  }
  if (Array.isArray(value)) {
    return value.map((v) => scrubPII(v, opts, depth + 1));
  }
  if (typeof value === "object") {
    const keys = combinePatterns(DEFAULT_PII_KEYS, opts?.additionalKeys);
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = isSensitiveKey(k, keys) ? REDACTED : scrubPII(v, opts, depth + 1);
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
  if (event.request && event.request.headers) {
    event.request.headers = scrubPII(
      event.request.headers,
      opts
    );
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
      message: typeof b.message === "string" ? scrubString(b.message) : b.message
    }));
  }
  if (typeof event.message === "string") {
    event.message = scrubString(event.message);
  }
  if (event.logentry && typeof event.logentry.message === "string") {
    event.logentry.message = scrubString(event.logentry.message);
  }
  if (event.exception?.values) {
    for (const ex of event.exception.values) {
      if (typeof ex.value === "string") {
        ex.value = scrubString(ex.value);
      }
    }
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
    if (text && opts.dropPatterns.some((re) => {
      re.lastIndex = 0;
      return re.test(text);
    })) {
      return true;
    }
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
