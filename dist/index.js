"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  createBeforeSend: () => createBeforeSend,
  isNoise: () => isNoise,
  normalizeRoute: () => normalizeRoute,
  phiBeforeSend: () => phiBeforeSend,
  scrubEvent: () => scrubEvent,
  scrubPII: () => scrubPII
});
module.exports = __toCommonJS(index_exports);
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
var TECHNICAL_VALUE = /^(?=.{1,128}$)(?!.*@)(?!\d{7,}$)[A-Za-z0-9_.:/<>()#$-]+$/;
var PACKAGE_RELEASE = /^(?=.{1,128}$)(?:@[A-Za-z0-9_.-]+\/)?[A-Za-z0-9_.-]+@v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$/;
var CODE_LOCATION = /\.(?:c|cc|cpp|cs|go|java|js|jsx|kt|mjs|cjs|php|py|rb|rs|swift|ts|tsx)(?::\d+)?$/i;
var TRACE_ID = /^[a-f0-9]{16,32}$/i;
function technicalString(value) {
  if (typeof value !== "string") return void 0;
  const scrubbed = scrubString(value);
  return TECHNICAL_VALUE.test(scrubbed) ? scrubbed : void 0;
}
function releaseString(value) {
  if (typeof value !== "string") return void 0;
  return technicalString(value) ?? (PACKAGE_RELEASE.test(value) ? value : void 0);
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
var ROUTE_WORD = /^[a-z][a-z0-9-]{0,39}$/;
var ROUTE = /^\/(?:(?:[a-z][a-z0-9-]{0,39}|:param)(?:\/(?:[a-z][a-z0-9-]{0,39}|:param))*)?$/;
var PARAM = ":param";
function normalizeRoute(path, words) {
  const allowed = new Set(words ?? []);
  const withoutOrigin = String(path).replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, "");
  const pathname = withoutOrigin.split(/[?#]/, 1)[0];
  const segments = pathname.split("/").filter((segment) => segment !== "").map(
    (segment) => ROUTE_WORD.test(segment) && allowed.has(segment) ? segment : PARAM
  );
  return `/${segments.join("/")}`.slice(0, 256);
}
function safeRoute(value, opts) {
  if (typeof value !== "string") return void 0;
  const route = normalizeRoute(value, opts?.routeWords);
  return ROUTE.test(route) ? route : void 0;
}
var TAG_RULES = {
  "http.method": (value) => /^[A-Z]{3,10}$/.test(value) ? value : void 0,
  "http.status_code": (value) => /^\d{3}$/.test(value) ? value : void 0,
  "error.code": (value) => /^(?:ERR_[A-Z_]{2,40}|UND_ERR_[A-Z_]{2,30}|EAI_[A-Z]{2,10}|E[A-Z]{3,15})$/.test(value) ? value : void 0,
  "http.route": (value, opts) => safeRoute(value, opts),
  runtime: (value) => ["browser", "ssr", "server"].includes(value) ? value : void 0,
  "http.host": (value, opts) => opts?.allowedHosts?.includes(value.toLowerCase()) ? value.toLowerCase() : void 0
};
function safeTags(tags, opts) {
  if (!tags || typeof tags !== "object" || Array.isArray(tags)) return void 0;
  const output = {};
  for (const [key, raw] of Object.entries(tags)) {
    const rule = TAG_RULES[key];
    if (!rule || typeof raw !== "string" && typeof raw !== "number") continue;
    const value = rule(String(raw), opts);
    if (value !== void 0) output[key] = value;
  }
  return Object.keys(output).length ? output : void 0;
}
var SAFE_MESSAGES = [
  [/^Request failed with status code \d{3}$/, (m) => m[0]],
  [/^Network Error$/, (m) => m[0]],
  [/^timeout of \d{1,7}ms exceeded$/, (m) => m[0]],
  [/^timeout exceeded$/, (m) => m[0]],
  [/^Request aborted$/, (m) => m[0]],
  [/^canceled$/, (m) => m[0]],
  [/^Failed to fetch$/, (m) => m[0]],
  [/^Load failed$/, (m) => m[0]],
  [/^NetworkError when attempting to fetch resource\.$/, (m) => m[0]],
  [/^The operation was aborted\.?$/, (m) => m[0]],
  [/^signal is aborted without reason$/, (m) => m[0]],
  [/^Script error\.?$/, (m) => m[0]],
  [/^ResizeObserver loop (?:completed with undelivered notifications|limit exceeded)\.?$/, (m) => m[0]],
  [/^Loading (?:CSS )?chunk \d{1,10} failed\.?$/, (m) => m[0]],
  [/^Minified React error #(\d{1,5})(?:[;.\s]|$)/, (m) => `Minified React error #${m[1]}`],
  [
    /^Hydration failed because the server rendered HTML didn't match the client\./,
    (m) => m[0]
  ]
];
function safeMessage(value) {
  if (typeof value === "string") {
    for (const [pattern, keep] of SAFE_MESSAGES) {
      const match = value.match(pattern);
      if (match) return keep(match);
    }
  }
  return REDACTED;
}
var BREADCRUMB_CATEGORIES = /* @__PURE__ */ new Set([
  "xhr",
  "fetch",
  "navigation",
  "http",
  "console",
  "ui.click",
  "ui.input",
  "sentry.event",
  "sentry.transaction"
]);
var REQUEST_CATEGORIES = /* @__PURE__ */ new Set(["xhr", "fetch", "http"]);
function strictEvent(event, opts) {
  const safe = copyTechnical(event, [
    "platform",
    "environment",
    "dist",
    "logger",
    "server_name"
  ]);
  const release = releaseString(event.release);
  if (release) safe.release = release;
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
      const category = typeof breadcrumb.category === "string" && BREADCRUMB_CATEGORIES.has(breadcrumb.category) ? breadcrumb.category : void 0;
      if (category) output.category = category;
      const data = breadcrumb.data;
      if (data && typeof data === "object" && (category === "navigation" || REQUEST_CATEGORIES.has(category ?? ""))) {
        const safeData = {};
        if (REQUEST_CATEGORIES.has(category ?? "")) {
          if (typeof data.method === "string" && /^[A-Z]{3,10}$/.test(data.method)) {
            safeData.method = data.method;
          }
          if (typeof data.status_code === "number" && Number.isInteger(data.status_code) && data.status_code >= 100 && data.status_code <= 599) {
            safeData.status_code = data.status_code;
          }
        }
        const route = safeRoute(data.route, opts);
        if (route) safeData.route = route;
        if (Object.keys(safeData).length) output.data = safeData;
      }
      return output;
    });
  }
  if (event.message !== void 0) safe.message = safeMessage(event.message);
  if (event.logentry !== void 0) {
    safe.logentry = { message: safeMessage(event.logentry.message) };
  }
  const tags = safeTags(event.tags, opts);
  if (tags) safe.tags = tags;
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
        if (exception.value !== void 0) output.value = safeMessage(exception.value);
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
  if (Array.isArray(event.fingerprint) && event.fingerprint.length) {
    const known = /* @__PURE__ */ new Set(["{{ default }}", ...Object.values(tags ?? {})]);
    for (const exception of safe.exception?.values ?? []) {
      if (typeof exception.type === "string") known.add(exception.type);
    }
    if (event.fingerprint.every((part) => typeof part === "string" && known.has(part))) {
      safe.fingerprint = [...event.fingerprint];
    }
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
function scrubEvent(event, opts) {
  if (!event || typeof event !== "object") return event;
  const safe = strictEvent(event, opts);
  const target = event;
  const safeRecord = safe;
  try {
    for (const key of Object.keys(target)) delete target[key];
    Object.assign(target, safe);
    const safeKeys = Object.keys(safe);
    if (Object.keys(target).length !== safeKeys.length || safeKeys.some((key) => target[key] !== safeRecord[key])) {
      return safe;
    }
    return event;
  } catch {
    return safe;
  }
}
var phiBeforeSend = (event) => scrubEvent(event);
var NOISE_LEVELS = /* @__PURE__ */ new Set(["warning", "info", "debug", "log"]);
function eventText(event, matchExceptionType = false) {
  const parts = [];
  if (typeof event.message === "string") parts.push(event.message);
  if (event.logentry && typeof event.logentry.message === "string") {
    parts.push(event.logentry.message);
  }
  for (const ex of event.exception?.values ?? []) {
    if (matchExceptionType && ex.type) parts.push(ex.type);
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
    const text = eventText(event, opts.matchExceptionType);
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  createBeforeSend,
  isNoise,
  normalizeRoute,
  phiBeforeSend,
  scrubEvent,
  scrubPII
});
