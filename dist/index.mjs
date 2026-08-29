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
var TECHNICAL_VALUE = /^[A-Za-z0-9_.:/+@<>()#$-]{1,256}$/;
var CODE_LOCATION = /\.(?:c|cc|cpp|cs|go|java|js|jsx|kt|mjs|cjs|php|py|rb|rs|swift|ts|tsx)(?::\d+)?$/i;
var TRACE_ID = /^[a-f0-9]{16,32}$/i;
function technicalString(value) {
  if (typeof value !== "string") return void 0;
  const scrubbed = scrubString(value);
  return TECHNICAL_VALUE.test(scrubbed) ? scrubbed : void 0;
}
function codeLocation(value) {
  if (typeof value !== "string") return void 0;
  const scrubbed = scrubString(value).split(/[?#]/, 1)[0].slice(0, 512);
  return CODE_LOCATION.test(scrubbed) ? scrubbed : void 0;
}
function copyTechnical(source, fields) {
  const output = {};
  for (const field of fields) {
    const value = technicalString(source[field]);
    if (value !== void 0) output[field] = value;
  }
  return output;
}
function strictEvent(event) {
  const safe = copyTechnical(event, [
    "platform",
    "environment",
    "release",
    "dist",
    "logger",
    "server_name"
  ]);
  if (typeof event.event_id === "string" && /^[a-f0-9]{32}$/i.test(event.event_id)) {
    safe.event_id = event.event_id;
  }
  if (typeof event.level === "string" && ["fatal", "error", "warning", "info", "debug", "log"].includes(
    event.level.toLowerCase()
  )) {
    safe.level = event.level.toLowerCase();
  }
  if (typeof event.timestamp === "number" || typeof event.timestamp === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(event.timestamp)) {
    safe.timestamp = event.timestamp;
  }
  if (event.request && typeof event.request.method === "string" && /^[A-Z]{3,10}$/.test(event.request.method)) {
    safe.request = { method: event.request.method };
  }
  if (event.breadcrumbs) {
    safe.breadcrumbs = event.breadcrumbs.map((breadcrumb) => {
      const output = {};
      const type = technicalString(breadcrumb.type);
      const level = technicalString(breadcrumb.level);
      if (type) output.type = type;
      if (level) output.level = level;
      if (typeof breadcrumb.timestamp === "number") {
        output.timestamp = breadcrumb.timestamp;
      }
      return output;
    });
  }
  if (event.message !== void 0) safe.message = REDACTED;
  if (event.logentry !== void 0) safe.logentry = { message: REDACTED };
  if (event.exception?.values) {
    safe.exception = {
      values: event.exception.values.map((exception) => {
        const output = copyTechnical(exception, [
          "type",
          "module"
        ]);
        if (typeof exception.thread_id === "number" || typeof exception.thread_id === "string" && /^[a-f0-9-]{1,64}$/i.test(exception.thread_id)) {
          output.thread_id = exception.thread_id;
        }
        if (exception.value !== void 0) output.value = REDACTED;
        const stacktrace = exception.stacktrace;
        if (stacktrace?.frames) {
          output.stacktrace = {
            frames: stacktrace.frames.map((frame) => {
              const safeFrame = copyTechnical(frame, [
                "function",
                "module",
                "instruction_addr",
                "package",
                "platform"
              ]);
              for (const field of ["filename", "abs_path"]) {
                const value = codeLocation(frame[field]);
                if (value) safeFrame[field] = value;
              }
              for (const field of ["lineno", "colno"]) {
                if (typeof frame[field] === "number") {
                  safeFrame[field] = frame[field];
                }
              }
              if (typeof frame.in_app === "boolean") {
                safeFrame.in_app = frame.in_app;
              }
              return safeFrame;
            })
          };
        }
        const mechanism = exception.mechanism;
        if (mechanism) {
          const safeMechanism = copyTechnical(mechanism, [
            "type",
            "exception_id",
            "parent_id"
          ]);
          for (const field of ["handled", "synthetic"]) {
            if (typeof mechanism[field] === "boolean") {
              safeMechanism[field] = mechanism[field];
            }
          }
          output.mechanism = safeMechanism;
        }
        return output;
      })
    };
  }
  const trace = event.contexts?.trace;
  if (trace && typeof trace === "object") {
    const source = trace;
    const safeTrace = copyTechnical(source, ["op", "status", "origin"]);
    for (const field of ["trace_id", "span_id", "parent_span_id"]) {
      if (typeof source[field] === "string" && TRACE_ID.test(source[field])) {
        safeTrace[field] = source[field];
      }
    }
    safe.contexts = { trace: safeTrace };
  }
  const debugMeta = event.debug_meta;
  if (debugMeta?.images) {
    safe.debug_meta = {
      images: debugMeta.images.map((image) => {
        const output = copyTechnical(image, [
          "type",
          "debug_id",
          "code_id",
          "image_addr",
          "image_size",
          "arch"
        ]);
        for (const field of ["code_file", "debug_file"]) {
          const value = codeLocation(image[field]);
          if (value) output[field] = value;
        }
        return output;
      })
    };
  }
  return safe;
}
function scrubPII(value, opts, depth = 0) {
  if (depth > MAX_DEPTH) return REDACTED;
  if (value == null) return value;
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
function scrubEvent(event) {
  if (!event || typeof event !== "object") return event;
  return strictEvent(event);
}
var phiBeforeSend = (event) => scrubEvent(event);
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
    return scrubEvent(event);
  };
}
export {
  createBeforeSend,
  isNoise,
  phiBeforeSend,
  scrubEvent,
  scrubPII
};
