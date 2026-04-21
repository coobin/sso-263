const http = require("http");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const APP_BASE_URL = requiredEnv("APP_BASE_URL");
const SESSION_SECRET = requiredEnv("SESSION_SECRET");

const AUTH_MODE = process.env.AUTH_MODE || "trusted_headers";
const AUTH_LOGIN_URL = process.env.AUTH_LOGIN_URL || "";
const AUTH_EXCHANGE_URL = process.env.AUTH_EXCHANGE_URL || "";

const MAIL_COOKIE_NAME = process.env.MAIL_COOKIE_NAME || "mail_sso_session";
const COOKIE_SECURE = boolEnv("COOKIE_SECURE", true);
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || "";
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 3600);

const PARTNER_ID = requiredEnv("PARTNER_ID");
const AUTH_CORP_ID = requiredEnv("AUTH_CORP_ID");
const API_SECRET = requiredEnv("API_SECRET");
const MAIL_SSO_BASE_URL =
  process.env.MAIL_SSO_BASE_URL ||
  "https://weixin.263.net/partner/web/third/mail/loginMail.do";

const AUTH_EXCHANGE_TOKEN = process.env.AUTH_EXCHANGE_TOKEN || "";
const AUTH_EXCHANGE_TIMEOUT_MS = Number(
  process.env.AUTH_EXCHANGE_TIMEOUT_MS || 5000,
);
const REMOTE_USER_HEADER = (
  process.env.REMOTE_USER_HEADER || "remote-user"
).toLowerCase();
const REMOTE_EMAIL_HEADER = (
  process.env.REMOTE_EMAIL_HEADER || "remote-email"
).toLowerCase();
const REMOTE_NAME_HEADER = (
  process.env.REMOTE_NAME_HEADER || "remote-name"
).toLowerCase();
const AUDIT_LOG_ENABLED = boolEnv("AUDIT_LOG_ENABLED", true);

validateAuthMode();

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function validateAuthMode() {
  const allowedModes = new Set(["trusted_headers", "exchange_code"]);
  if (!allowedModes.has(AUTH_MODE)) {
    throw new Error(
      `Invalid AUTH_MODE: ${AUTH_MODE}. Expected trusted_headers or exchange_code`,
    );
  }
  if (AUTH_MODE === "exchange_code") {
    if (!AUTH_LOGIN_URL) {
      throw new Error("AUTH_LOGIN_URL is required when AUTH_MODE=exchange_code");
    }
    if (!AUTH_EXCHANGE_URL) {
      throw new Error("AUTH_EXCHANGE_URL is required when AUTH_MODE=exchange_code");
    }
  }
}

function boolEnv(name, defaultValue) {
  const value = process.env[name];
  if (value == null || value === "") return defaultValue;
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
}

function json(res, statusCode, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function redirect(res, location, headers = {}) {
  res.writeHead(302, { Location: location, ...headers });
  res.end();
}

function badRequest(res, message) {
  json(res, 400, { error: message });
}

function serverError(res, message, details) {
  const payload = { error: message };
  if (details) payload.details = details;
  json(res, 500, payload);
}

function firstHeaderValue(value) {
  if (Array.isArray(value)) return value[0] || "";
  return value || "";
}

function decodeHeaderText(value) {
  const text = String(value || "").trim();
  if (!text) return "";

  try {
    const decoded = decodeURIComponent(text);
    if (decoded !== text) return decoded;
  } catch {
    // Header was not URL encoded.
  }

  const utf8Text = Buffer.from(text, "latin1").toString("utf8");
  return utf8Text.includes("\uFFFD") ? text : utf8Text;
}

function getClientIp(req) {
  const forwardedFor = firstHeaderValue(req.headers["x-forwarded-for"]);
  if (forwardedFor) return forwardedFor.split(",")[0].trim();

  const realIp = firstHeaderValue(req.headers["x-real-ip"]);
  if (realIp) return realIp.trim();

  return req.socket.remoteAddress || "";
}

function auditLog(req, event, fields = {}) {
  if (!AUDIT_LOG_ENABLED) return;

  const entry = {
    ts: new Date().toISOString(),
    level: "info",
    event,
    authMode: AUTH_MODE,
    method: req.method,
    path: new URL(req.url, APP_BASE_URL).pathname,
    ip: getClientIp(req),
    remoteAddress: req.socket.remoteAddress || "",
    xForwardedFor: firstHeaderValue(req.headers["x-forwarded-for"]),
    xRealIp: firstHeaderValue(req.headers["x-real-ip"]),
    userAgent: firstHeaderValue(req.headers["user-agent"]),
    ...fields,
  };

  console.log(JSON.stringify(entry));
}

function auditUser(user) {
  if (!user) return {};
  return {
    email: user.email || "",
    userId: user.userId || "",
    name: user.name || "",
  };
}

function parseCookies(req) {
  const cookieHeader = req.headers.cookie || "";
  const cookies = {};

  for (const part of cookieHeader.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const index = trimmed.indexOf("=");
    if (index === -1) continue;
    const key = trimmed.slice(0, index);
    const value = trimmed.slice(index + 1);
    cookies[key] = decodeURIComponent(value);
  }

  return cookies;
}

function createSessionCookie(user) {
  const payload = {
    email: user.email,
    userId: user.userId || user.email,
    name: user.name || "",
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = signValue(encodedPayload);
  const cookieValue = `${encodedPayload}.${signature}`;
  return serializeCookie(MAIL_COOKIE_NAME, cookieValue, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "Lax",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
    domain: COOKIE_DOMAIN || undefined,
  });
}

function clearSessionCookie() {
  return serializeCookie(MAIL_COOKIE_NAME, "", {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "Lax",
    path: "/",
    expires: new Date(0),
    domain: COOKIE_DOMAIN || undefined,
  });
}

function readSession(req) {
  const cookies = parseCookies(req);
  const raw = cookies[MAIL_COOKIE_NAME];
  if (!raw) return null;

  const [encodedPayload, providedSignature] = raw.split(".");
  if (!encodedPayload || !providedSignature) return null;

  const expectedSignature = signValue(encodedPayload);
  const signatureBuffer = Buffer.from(providedSignature);
  const expectedBuffer = Buffer.from(expectedSignature);
  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf-8"),
    );
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    if (!payload.email) return null;
    return payload;
  } catch {
    return null;
  }
}

function signValue(value) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(value)
    .digest("base64url");
}

function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge != null) parts.push(`Max-Age=${options.maxAge}`);
  if (options.domain) parts.push(`Domain=${options.domain}`);
  if (options.path) parts.push(`Path=${options.path}`);
  if (options.expires) parts.push(`Expires=${options.expires.toUTCString()}`);
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  return parts.join("; ");
}

function detectPlatform(userAgent) {
  const ua = (userAgent || "").toLowerCase();
  if (ua.includes("android")) return "android";
  if (ua.includes("iphone") || ua.includes("ipad") || ua.includes("ios")) {
    return "iphone";
  }
  return "windows";
}

function getTrustedHeaderUser(req) {
  const email = req.headers[REMOTE_EMAIL_HEADER];
  if (!email || Array.isArray(email)) return null;

  const userIdHeader = req.headers[REMOTE_USER_HEADER];
  const nameHeader = req.headers[REMOTE_NAME_HEADER];
  const userId = Array.isArray(userIdHeader) ? email : userIdHeader || email;
  const name = Array.isArray(nameHeader) ? "" : nameHeader || "";

  return {
    email: String(email).trim(),
    userId: String(userId).trim(),
    name: decodeHeaderText(name),
  };
}

function buildAuthLoginUrl(req) {
  if (!AUTH_LOGIN_URL) {
    throw new Error("AUTH_LOGIN_URL is not configured");
  }
  const authUrl = new URL(AUTH_LOGIN_URL);
  authUrl.searchParams.set(
    "redirect_uri",
    `${APP_BASE_URL}/auth/callback`,
  );
  authUrl.searchParams.set("state", buildState(req));
  return authUrl.toString();
}

function buildState(req) {
  const next = extractNext(req.url);
  const payload = Buffer.from(
    JSON.stringify({ next, ts: Date.now() }),
    "utf-8",
  ).toString("base64url");
  const signature = signValue(payload);
  return `${payload}.${signature}`;
}

function parseState(state) {
  if (!state) return "/";
  const [payload, signature] = state.split(".");
  if (!payload || !signature) return "/";
  const expectedSignature = signValue(payload);
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expectedSignature);
  if (
    signatureBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedBuffer)
  ) {
    return "/";
  }

  try {
    const parsed = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf-8"),
    );
    return sanitizeNext(parsed.next);
  } catch {
    return "/";
  }
}

function sanitizeNext(next) {
  if (!next || typeof next !== "string") return "/";
  if (!next.startsWith("/")) return "/";
  if (next.startsWith("//")) return "/";
  return next;
}

function extractNext(rawUrl) {
  const url = new URL(rawUrl, APP_BASE_URL);
  return sanitizeNext(url.searchParams.get("next") || "/sso/mail");
}

async function exchangeCodeForUser(code) {
  if (!AUTH_EXCHANGE_URL) {
    throw new Error("AUTH_EXCHANGE_URL is not configured");
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), AUTH_EXCHANGE_TIMEOUT_MS);

  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  if (AUTH_EXCHANGE_TOKEN) {
    headers.Authorization = `Bearer ${AUTH_EXCHANGE_TOKEN}`;
  }

  try {
    const response = await fetch(AUTH_EXCHANGE_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ code }),
      signal: controller.signal,
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(
        `Auth exchange failed with ${response.status}: ${JSON.stringify(payload)}`,
      );
    }

    const email =
      payload.email ||
      payload.user?.email ||
      payload.data?.email ||
      payload.data?.user?.email;
    const userId =
      payload.userId ||
      payload.userid ||
      payload.user?.userId ||
      payload.user?.id ||
      payload.data?.userId ||
      payload.data?.userid ||
      payload.data?.user?.userId ||
      email;
    const name =
      payload.name ||
      payload.user?.name ||
      payload.data?.name ||
      payload.data?.user?.name ||
      "";

    if (!email) {
      throw new Error(`Auth exchange succeeded but email is missing: ${JSON.stringify(payload)}`);
    }

    return { email, userId, name };
  } finally {
    clearTimeout(timer);
  }
}

function build263Url(req, session) {
  const loginPlatform = detectPlatform(req.headers["user-agent"]);
  const type = "READMAIL";
  const userid = session.email;
  const timestamp = String(Date.now());
  const signSource =
    API_SECRET +
    loginPlatform +
    type +
    PARTNER_ID +
    AUTH_CORP_ID +
    userid +
    timestamp;
  const sign = crypto.createHash("md5").update(signSource, "utf8").digest("hex");

  const ssoUrl = new URL(MAIL_SSO_BASE_URL);
  ssoUrl.searchParams.set("loginPlatform", loginPlatform);
  ssoUrl.searchParams.set("type", type);
  ssoUrl.searchParams.set("partnerid", PARTNER_ID);
  ssoUrl.searchParams.set("authcorpid", AUTH_CORP_ID);
  ssoUrl.searchParams.set("userid", userid);
  ssoUrl.searchParams.set("timestamp", timestamp);
  ssoUrl.searchParams.set("sign", sign);

  return ssoUrl.toString();
}

function ensureCompanyMailbox(email) {
  return String(email).toLowerCase().endsWith(`@${AUTH_CORP_ID.toLowerCase()}`);
}

function resolveAuthenticatedUser(req) {
  if (AUTH_MODE === "trusted_headers") {
    return getTrustedHeaderUser(req);
  }
  return readSession(req);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, APP_BASE_URL);

  try {
    if (req.method === "GET" && url.pathname === "/healthz") {
      return json(res, 200, { ok: true });
    }

    if (req.method === "GET" && url.pathname === "/logout") {
      auditLog(req, "logout");
      return redirect(res, "/", { "Set-Cookie": clearSessionCookie() });
    }

    if (req.method === "GET" && url.pathname === "/") {
      const user = resolveAuthenticatedUser(req);
      if (!user) {
        auditLog(req, "auth_missing", {
          status: 401,
          reason:
            AUTH_MODE === "trusted_headers"
              ? "missing_trusted_auth_headers"
              : "missing_session",
        });
        if (AUTH_MODE === "trusted_headers") {
          return json(res, 401, {
            error:
              "Missing trusted auth headers. Ensure Nginx Proxy Manager is forwarding Authelia Remote-* headers to this service.",
          });
        }
        auditLog(req, "auth_login_redirect", { status: 302 });
        return redirect(res, buildAuthLoginUrl(req));
      }
      auditLog(req, "auth_entry_success", {
        status: 302,
        ...auditUser(user),
      });
      return redirect(res, "/sso/mail");
    }

    if (req.method === "GET" && url.pathname === "/auth/callback") {
      if (AUTH_MODE !== "exchange_code") {
        return json(res, 404, { error: "Not found" });
      }
      const code = url.searchParams.get("code");
      if (!code) {
        auditLog(req, "auth_callback_rejected", {
          status: 400,
          reason: "missing_code",
        });
        return badRequest(res, "Missing code");
      }

      const user = await exchangeCodeForUser(code);
      if (!ensureCompanyMailbox(user.email)) {
        auditLog(req, "auth_callback_rejected", {
          status: 403,
          reason: "mailbox_domain_not_allowed",
          ...auditUser(user),
        });
        return json(res, 403, {
          error: `Only @${AUTH_CORP_ID} mailboxes can use this entrypoint`,
        });
      }

      const sessionCookie = createSessionCookie(user);
      const next = parseState(url.searchParams.get("state"));
      auditLog(req, "auth_callback_success", {
        status: 302,
        next,
        ...auditUser(user),
      });
      return redirect(res, next, { "Set-Cookie": sessionCookie });
    }

    if (req.method === "GET" && url.pathname === "/sso/mail") {
      const user = resolveAuthenticatedUser(req);
      if (!user) {
        auditLog(req, "mail_sso_rejected", {
          status: AUTH_MODE === "trusted_headers" ? 401 : 302,
          reason:
            AUTH_MODE === "trusted_headers"
              ? "missing_trusted_auth_headers"
              : "missing_session",
        });
        if (AUTH_MODE === "trusted_headers") {
          return json(res, 401, {
            error:
              "Missing trusted auth headers. Ensure Nginx Proxy Manager and Authelia are correctly configured.",
          });
        }
        return redirect(res, buildAuthLoginUrl(req));
      }
      if (!ensureCompanyMailbox(user.email)) {
        auditLog(req, "mail_sso_rejected", {
          status: 403,
          reason: "mailbox_domain_not_allowed",
          ...auditUser(user),
        });
        return json(res, 403, {
          error: `Only @${AUTH_CORP_ID} mailboxes can use this entrypoint`,
        });
      }
      auditLog(req, "mail_sso_success", {
        status: 302,
        platform: detectPlatform(req.headers["user-agent"]),
        ...auditUser(user),
      });
      return redirect(res, build263Url(req, user));
    }

    if (req.method === "GET" && url.pathname === "/debug/session") {
      const session = resolveAuthenticatedUser(req);
      return json(res, 200, {
        authenticated: Boolean(session),
        session: session || null,
        authMode: AUTH_MODE,
      });
    }

    return json(res, 404, { error: "Not found" });
  } catch (error) {
    auditLog(req, "request_error", {
      status: 500,
      error: error.message,
    });
    return serverError(res, "Unexpected server error", error.message);
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`sso-263 listening on port ${PORT}`);
});
