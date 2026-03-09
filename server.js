require("dotenv").config();
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const path = require("path");
const { GoogleGenAI } = require("@google/genai");

const app = express();

function readPositiveInt(name, fallback) {
  const value = Number(process.env[name]);
  if (Number.isFinite(value) && value > 0) {
    return Math.floor(value);
  }
  return fallback;
}

function readNonNegativeInt(name, fallback) {
  const value = Number(process.env[name]);
  if (Number.isFinite(value) && value >= 0) {
    return Math.floor(value);
  }
  return fallback;
}

function parseCorsOrigins(rawOrigins) {
  return String(rawOrigins)
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function parseModelList(raw, fallback) {
  const parsed = String(raw || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (parsed.length > 0) return [...new Set(parsed)];
  return [...new Set(fallback)];
}

function normalizeAuthUsers(rawUsers, fallbackUsers) {
  if (!Array.isArray(rawUsers) || rawUsers.length === 0) {
    return fallbackUsers;
  }

  const users = [];
  const seenAccounts = new Set();
  for (let i = 0; i < rawUsers.length; i++) {
    const raw = rawUsers[i];
    if (!raw || typeof raw !== "object") continue;

    const account = String(raw.account || "").trim();
    const passwordHash = String(raw.passwordHash || "").trim().toLowerCase();
    const displayName = String(raw.displayName || account || "").trim();
    const id = String(raw.id || account || "").trim();
    if (!account || !passwordHash || !id || seenAccounts.has(account)) continue;
    if (!/^[a-f0-9]{64}$/.test(passwordHash)) continue;

    seenAccounts.add(account);
    users.push({
      id,
      account,
      passwordHash,
      displayName: displayName || account,
    });
  }
  return users.length > 0 ? users : fallbackUsers;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex");
}

function verifyPasswordHash(rawPassword, expectedHash) {
  if (!/^[a-f0-9]{64}$/.test(String(expectedHash || ""))) return false;
  const actual = Buffer.from(sha256Hex(rawPassword), "hex");
  const expected = Buffer.from(String(expectedHash), "hex");
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

const NODE_ENV = process.env.NODE_ENV || "development";
const PORT = readPositiveInt("PORT", 3000);
const REQUEST_TIMEOUT_MS = readPositiveInt("REQUEST_TIMEOUT_MS", 90_000);
const MIN_REQUEST_TIMEOUT_MS = readPositiveInt("MIN_REQUEST_TIMEOUT_MS", 20_000);
const MAX_REQUEST_TIMEOUT_MS = readPositiveInt("MAX_REQUEST_TIMEOUT_MS", 300_000);
const WEB_SEARCH_MIN_TIMEOUT_MS = readPositiveInt("WEB_SEARCH_MIN_TIMEOUT_MS", 90_000);
const COMPLEX_QUESTION_MIN_TIMEOUT_MS = readPositiveInt("COMPLEX_QUESTION_MIN_TIMEOUT_MS", 120_000);
const COMPLEX_QUESTION_CHAR_THRESHOLD = readPositiveInt("COMPLEX_QUESTION_CHAR_THRESHOLD", 220);
const MAX_ATTACHMENTS = readPositiveInt("MAX_ATTACHMENTS", 4);
const MAX_TEXT_ATTACHMENT_CHARS = readPositiveInt("MAX_TEXT_ATTACHMENT_CHARS", 120_000);
const MAX_BASE64_ATTACHMENT_CHARS = readPositiveInt("MAX_BASE64_ATTACHMENT_CHARS", 8_000_000);
const HISTORY_MAX_MESSAGES = readPositiveInt("HISTORY_MAX_MESSAGES", 40);
const HISTORY_MESSAGE_MAX_CHARS = readPositiveInt("HISTORY_MESSAGE_MAX_CHARS", 6000);
const RATE_LIMIT_WINDOW_MS = readPositiveInt("RATE_LIMIT_WINDOW_MS", 60_000);
const RATE_LIMIT_MAX_REQUESTS = readPositiveInt("RATE_LIMIT_MAX_REQUESTS", 20);
const TRUST_PROXY = process.env.TRUST_PROXY || "1";
const ALLOWED_CORS_ORIGINS = parseCorsOrigins(process.env.CORS_ORIGINS || "");
const AUTH_TOKEN_TTL_MS = readPositiveInt("AUTH_TOKEN_TTL_MS", 24 * 60 * 60 * 1000);
const CONTEXT_TURN_PAIRS = readPositiveInt("CONTEXT_TURN_PAIRS", 6);
const CONTEXT_MAX_MESSAGES = readNonNegativeInt("CONTEXT_MAX_MESSAGES", 0);
const CONTEXT_TTL_MS = readPositiveInt("CONTEXT_TTL_MS", 30 * 24 * 60 * 60 * 1000);

const DEFAULT_ALLOWED_MODELS = [
  "gemini-3.1-pro",
  "gemini-3-deep-think",
  "gemini-2.5-flash",
  "gemma-3-1b-it",
  "gemma-3-4b-it",
];
const RESERVED_PAID_MODELS = parseModelList(process.env.GEMINI_RESERVED_MODELS || "", []);
const ENV_DEFAULT_MODEL = (process.env.GEMINI_MODEL || "gemini-3.1-pro").trim();
const ALLOWED_MODELS = [
  ...new Set([
    ...parseModelList(process.env.GEMINI_ALLOWED_MODELS || "", DEFAULT_ALLOWED_MODELS),
    ...RESERVED_PAID_MODELS,
  ]),
];
const SUPPORTED_MODELS = new Set(ALLOWED_MODELS);
const DEFAULT_MODEL = SUPPORTED_MODELS.has(ENV_DEFAULT_MODEL) ? ENV_DEFAULT_MODEL : ALLOWED_MODELS[0] || "gemini-3.1-pro";

const SUPPORTED_BINARY_MIME_TYPES = new Set([
  "application/pdf",
  "image/png",
  "image/jpeg",
  "image/webp",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
]);

const DEFAULT_AUTH_USERS = [
  {
    id: "jaylaw-ai",
    account: "jaylaw-ai",
    passwordHash: "198e9be47ee18789934365c850742405a3c770f02c709a75fefe19b3e3897641",
    displayName: "JayLaw",
  },
  {
    id: "jiexinlaw-ai",
    account: "jiexinlaw-ai",
    passwordHash: "729cfbddba49f469f5858cda703441ab5d72f0c57d3e4f2abb6cc4460639bbfb",
    displayName: "JiexinLaw",
  },
];
const AUTH_USERS = normalizeAuthUsers(
  (() => {
    try {
      return JSON.parse(String(process.env.AUTH_USERS_JSON || "[]"));
    } catch {
      return [];
    }
  })(),
  DEFAULT_AUTH_USERS
);
const USER_BY_ACCOUNT = new Map(AUTH_USERS.map((user) => [user.account, user]));
const displayNameStore = new Map(AUTH_USERS.map((user) => [user.id, user.displayName]));

const RESPONSE_STYLE_INSTRUCTION = `
【角色设定】
你是一位拥有超过几十年实务经验和学术经验的中国资深商事律师及仲裁员。你的工作语言为中文和英文。

【总则】
回答必须严谨、客观、逻辑严密。默认采用中文输出；若用户明确要求英文或双语，再切换语言。

【守则 1：法理与反幻觉绝对红线】
所有法律分析必须严格依据现行有效的中国法律法规、司法解释及最高人民法院指导性案例/公报案例、法院公开裁判文书。
严禁捏造法条、案号、法规名称、裁判观点。
若对特定法条或案例无法确定，必须明确写明“目前无法确定该特定法条/案例”，不得编造。

【守则 2：案卷绝对优先原则（附件处理）】
如存在附件，必须先引用附件中的具体条款或原文段落作为“事实依据”，再进行法律适用分析。
禁止脱离附件内容空泛论证。若附件与问题不相关，需明确指出不相关并解释原因。

【守则 3：联网实证与精准溯源】
涉及最新法律法规、监管动态、热点案例时，必须进行联网核验，并优先使用官方来源（人大网、最高法、政府官网等）与最新有效文本。
引用网络资料或法规时，必须在对应句末使用 Markdown 超链接标注原文来源，确保可点击核验。
若无法提供可核验来源链接，必须明确说明“当前无法提供可核验来源链接”。

【守则 4：专业法律翻译标准】
进行法律翻译时，禁止口语化表达；需使用法律专业术语并注意大陆法系与英美法系术语差异。
对于 Equity、Consideration、惩罚性赔偿等术语，除翻译外应在括号内补充关键法律内涵，避免歧义。

【守则 5：逻辑输出框架与风险隔离】
保持中立专业语气，不使用“保证”“绝对”等承诺性措辞。
必要时提示商业风险、诉讼/仲裁不确定性与证据不足风险。

【输出结构（默认）】
1) 结论摘要（2-5行）
2) 事实依据（优先引用附件原文；如无附件则写“无附件事实依据”）
3) 法律依据（法条名称+要点；若使用外部资料必须带 Markdown 链接）
4) 法律分析
5) 争议与风险
6) 实务建议
7) 待补充事实（如无则写“无”）
`;

const WEB_SEARCH_FORCE_KEYWORDS = [
  "最新",
  "最近",
  "新规",
  "监管",
  "政策",
  "修订",
  "废止",
  "热点",
  "时效性",
  "指导性案例",
  "公报案例",
  "today",
  "latest",
  "recent",
  "new regulation",
  "updated law",
];

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

const sessions = new Map();
const conversationContexts = new Map();
const chatRateLimiter = createInMemoryRateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  maxRequests: RATE_LIMIT_MAX_REQUESTS,
});

app.disable("x-powered-by");
app.set("trust proxy", TRUST_PROXY);
app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        callback(null, true);
        return;
      }
      if (ALLOWED_CORS_ORIGINS.length === 0) {
        callback(null, true);
        return;
      }
      callback(null, ALLOWED_CORS_ORIGINS.includes(origin));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json({ limit: "25mb" }));
app.use(express.static(path.join(__dirname)));

setInterval(() => {
  const now = Date.now();

  for (const [token, session] of sessions.entries()) {
    if (!session || session.expiresAt <= now) {
      sessions.delete(token);
    }
  }

  for (const [key, context] of conversationContexts.entries()) {
    if (!context || context.updatedAt + CONTEXT_TTL_MS <= now) {
      conversationContexts.delete(key);
    }
  }
}, 30_000).unref();

app.get("/health", (_req, res) => {
  res.json({ success: true, message: "ok" });
});

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/api/login", (req, res) => {
  const account = String(req.body?.account || "").trim();
  const password = String(req.body?.password || "");

  if (!account || !password) {
    return res.status(400).json({
      success: false,
      message: "账号和密码不能为空",
    });
  }

  const user = USER_BY_ACCOUNT.get(account);
  if (!user || !verifyPasswordHash(password, user.passwordHash)) {
    return res.status(401).json({
      success: false,
      message: "账号或密码错误",
    });
  }

  const token = crypto.randomBytes(24).toString("hex");
  const now = Date.now();
  sessions.set(token, {
    token,
    userId: user.id,
    account: user.account,
    expiresAt: now + AUTH_TOKEN_TTL_MS,
  });

  return res.json({
    success: true,
    token,
    user: {
      id: user.id,
      account: user.account,
      displayName: displayNameStore.get(user.id) || user.displayName,
    },
  });
});

app.get("/api/session", requireAuth, (req, res) => {
  return res.json({
    success: true,
    user: req.authUser,
  });
});

app.post("/api/logout", requireAuth, (req, res) => {
  sessions.delete(req.authToken);
  return res.json({ success: true });
});

app.post("/api/profile", requireAuth, (req, res) => {
  const displayName = String(req.body?.displayName || "").trim().slice(0, 32);
  if (!displayName) {
    return res.status(400).json({
      success: false,
      message: "显示名称不能为空",
    });
  }

  displayNameStore.set(req.authUser.id, displayName);

  for (const session of sessions.values()) {
    if (session.userId === req.authUser.id) {
      session.expiresAt = Date.now() + AUTH_TOKEN_TTL_MS;
    }
  }

  return res.json({
    success: true,
    user: {
      ...req.authUser,
      displayName,
    },
  });
});

app.get("/api/models", requireAuth, (_req, res) => {
  return res.json({
    success: true,
    models: ALLOWED_MODELS,
    defaultModel: DEFAULT_MODEL,
  });
});

app.post("/api/chat", chatRateLimiter, requireAuth, handleChat);
app.post("/ask", chatRateLimiter, requireAuth, handleChat);

function extractBearerToken(req) {
  const authHeader = String(req.headers?.authorization || "").trim();
  if (!authHeader.toLowerCase().startsWith("bearer ")) return "";
  return authHeader.slice(7).trim();
}

function requireAuth(req, res, next) {
  const token = extractBearerToken(req);
  if (!token) {
    return res.status(401).json({
      success: false,
      message: "未登录或登录已失效",
    });
  }

  const session = sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return res.status(401).json({
      success: false,
      message: "登录状态已过期，请重新登录",
    });
  }

  session.expiresAt = Date.now() + AUTH_TOKEN_TTL_MS;
  req.authToken = token;
  req.authUser = {
    id: session.userId,
    account: session.account,
    displayName: displayNameStore.get(session.userId) || session.account,
  };
  next();
}

function normalizeModelValue(value) {
  return String(value || "").trim();
}

function resolveRequestModel(requestModel) {
  const normalizedRequested = normalizeModelValue(requestModel);
  if (normalizedRequested) {
    if (!SUPPORTED_MODELS.has(normalizedRequested)) {
      return { ok: false, model: "", reason: "UNSUPPORTED_MODEL" };
    }
    return { ok: true, model: normalizedRequested, reason: "REQUESTED" };
  }
  return { ok: true, model: DEFAULT_MODEL, reason: "DEFAULT" };
}

function withTimeout(promise, timeoutMs) {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`模型服务请求超时（>${timeoutMs}ms）`)), timeoutMs);
    }),
  ]);
}

function normalizeErrorMessage(error) {
  const message = String(error?.message || "unknown error");
  return message.length > 500 ? `${message.slice(0, 500)}...` : message;
}

function isTransientError(error) {
  const raw = normalizeErrorMessage(error);
  const message = normalizeErrorMessage(error).toLowerCase();
  return (
    message.includes("timeout") ||
    message.includes("timed out") ||
    message.includes("503") ||
    message.includes("temporarily") ||
    message.includes("unavailable") ||
    message.includes("econnreset") ||
    message.includes("etimedout") ||
    raw.includes("超时")
  );
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseUpstreamErrorPayload(error) {
  const rawMessage = String(error?.message || "unknown error");
  try {
    const parsed = JSON.parse(rawMessage);
    const payload = parsed?.error;
    if (!payload || typeof payload !== "object") return null;
    const code = Number(payload.code);
    const status = String(payload.status || "");
    const message = String(payload.message || rawMessage);
    return {
      code: Number.isFinite(code) ? code : 0,
      status,
      message,
    };
  } catch {
    return null;
  }
}

function mapUpstreamError(error) {
  const payload = parseUpstreamErrorPayload(error);
  const raw = normalizeErrorMessage(error);
  const lower = raw.toLowerCase();
  const payloadMessage = String(payload?.message || "").toLowerCase();

  if (
    payload?.code === 429 ||
    payload?.status === "RESOURCE_EXHAUSTED" ||
    payloadMessage.includes("quota exceeded") ||
    payloadMessage.includes("rate limit")
  ) {
    return {
      statusCode: 429,
      errorCode: "UPSTREAM_QUOTA_EXCEEDED",
      userMessage: "当前模型配额不足，请切换其他模型或稍后重试",
      detail: payload?.message || raw,
    };
  }

  if (
    payload?.code === 404 ||
    payload?.status === "NOT_FOUND" ||
    payloadMessage.includes("is not found for api version") ||
    (lower.includes("model") && lower.includes("not found"))
  ) {
    return {
      statusCode: 502,
      errorCode: "UPSTREAM_MODEL_NOT_AVAILABLE",
      userMessage: "当前模型不可用，请切换模型后重试",
      detail: payload?.message || raw,
    };
  }

  if (
    lower.includes("timeout") ||
    lower.includes("timed out") ||
    lower.includes("aborted") ||
    raw.includes("超时")
  ) {
    return {
      statusCode: 504,
      errorCode: "UPSTREAM_TIMEOUT",
      userMessage: "请求超时，请稍后重试",
      detail: payload?.message || raw,
    };
  }

  if (
    lower.includes("fetch failed") ||
    lower.includes("econnrefused") ||
    lower.includes("network") ||
    lower.includes("proxy")
  ) {
    return {
      statusCode: 502,
      errorCode: "UPSTREAM_NETWORK_ERROR",
      userMessage: "后端到模型服务网络请求失败，请检查网络与代理配置",
      detail: payload?.message || raw,
    };
  }

  return {
    statusCode: 500,
    errorCode: "UNKNOWN_UPSTREAM_ERROR",
    userMessage: "模型调用失败，请稍后重试",
    detail: payload?.message || raw,
  };
}

function normalizeFilename(name, fallbackName) {
  const raw = typeof name === "string" ? name.trim() : "";
  if (!raw) return fallbackName;
  return raw.slice(0, 120);
}

function normalizeAttachments(rawAttachments) {
  if (!Array.isArray(rawAttachments)) {
    return [];
  }

  const normalized = [];
  for (let i = 0; i < rawAttachments.length && normalized.length < MAX_ATTACHMENTS; i++) {
    const item = rawAttachments[i];
    if (!item || typeof item !== "object") {
      continue;
    }

    const name = normalizeFilename(item.name, `附件${i + 1}`);
    const mimeType = typeof item.mimeType === "string" ? item.mimeType.trim().toLowerCase() : "";
    const text = typeof item.text === "string" ? item.text.trim() : "";
    const data = typeof item.data === "string" ? item.data.trim() : "";

    if (text) {
      normalized.push({
        kind: "text",
        name,
        mimeType: mimeType || "text/plain",
        text: text.slice(0, MAX_TEXT_ATTACHMENT_CHARS),
      });
      continue;
    }

    if (!data || !mimeType || !SUPPORTED_BINARY_MIME_TYPES.has(mimeType)) {
      continue;
    }
    if (data.length > MAX_BASE64_ATTACHMENT_CHARS) {
      continue;
    }

    normalized.push({
      kind: "binary",
      name,
      mimeType,
      data,
    });
  }

  return normalized;
}

function buildUserParts(userMessage, attachments) {
  const fallbackQuestion = "请结合附件内容给出关键结论。";
  const question = userMessage || fallbackQuestion;
  const parts = [
    {
      text: `用户问题：${question}`,
    },
  ];

  if (attachments.length === 0) {
    return parts;
  }

  parts.push({
    text: `以下是用户上传的 ${attachments.length} 个附件，请将附件内容与问题一起分析后再作答。`,
  });

  for (let i = 0; i < attachments.length; i++) {
    const attachment = attachments[i];
    const title = `附件${i + 1}：${attachment.name}`;

    if (attachment.kind === "text") {
      parts.push({ text: `${title}（${attachment.mimeType}）` });
      parts.push({ text: attachment.text });
      continue;
    }

    parts.push({ text: `${title}（${attachment.mimeType}）` });
    parts.push({
      inlineData: {
        mimeType: attachment.mimeType,
        data: attachment.data,
      },
    });
  }

  parts.push({
    text: "请优先依据附件内容回答。如果附件信息不足，请明确指出缺失信息。",
  });

  return parts;
}

function normalizeConversationId(value) {
  const raw = String(value || "").trim();
  if (!raw) return "default";
  const safe = raw.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 120);
  return safe || "default";
}

function normalizeConversationHistory(rawHistory) {
  if (!Array.isArray(rawHistory)) return [];
  const normalized = [];

  for (let i = 0; i < rawHistory.length && normalized.length < HISTORY_MAX_MESSAGES; i++) {
    const item = rawHistory[i];
    if (!item || typeof item !== "object") continue;

    const rawRole = String(item.role || "").trim().toLowerCase();
    const role = rawRole === "user" ? "user" : (rawRole === "model" || rawRole === "ai" ? "model" : "");
    const content = String(item.content || "").trim();
    if (!role || !content) continue;

    normalized.push({
      role,
      parts: [{ text: content.slice(0, HISTORY_MESSAGE_MAX_CHARS) }],
    });
  }
  return normalized;
}

function resolveRequestTimeoutMs({ requestedTimeoutMs, userMessage, useWebSearch, model }) {
  const minTimeout = Math.min(MIN_REQUEST_TIMEOUT_MS, MAX_REQUEST_TIMEOUT_MS);
  const maxTimeout = Math.max(MIN_REQUEST_TIMEOUT_MS, MAX_REQUEST_TIMEOUT_MS);
  let timeoutMs = REQUEST_TIMEOUT_MS;

  const raw = Number(requestedTimeoutMs);
  if (Number.isFinite(raw) && raw > 0) {
    timeoutMs = Math.floor(raw);
  }

  timeoutMs = Math.max(minTimeout, Math.min(maxTimeout, timeoutMs));
  const messageLength = String(userMessage || "").length;
  const isComplexQuestion = messageLength >= COMPLEX_QUESTION_CHAR_THRESHOLD;
  const isDeepThinkModel = String(model || "").toLowerCase().includes("deep-think");

  if (useWebSearch) {
    timeoutMs = Math.max(timeoutMs, WEB_SEARCH_MIN_TIMEOUT_MS);
  }
  if (isComplexQuestion || isDeepThinkModel) {
    timeoutMs = Math.max(timeoutMs, COMPLEX_QUESTION_MIN_TIMEOUT_MS);
  }

  timeoutMs = Math.max(minTimeout, Math.min(maxTimeout, timeoutMs));
  return timeoutMs;
}

function shouldForceWebSearchByQuestion(question) {
  const value = String(question || "").toLowerCase();
  if (!value) return false;
  return WEB_SEARCH_FORCE_KEYWORDS.some((keyword) => value.includes(keyword.toLowerCase()));
}

function getConversationContext(userId, conversationId) {
  const key = `${userId}::${conversationId}`;
  const existing = conversationContexts.get(key);
  if (existing) {
    existing.updatedAt = Date.now();
    return existing;
  }
  const created = {
    messages: [],
    updatedAt: Date.now(),
  };
  conversationContexts.set(key, created);
  return created;
}

function buildConversationContents({ context, historyMessages, currentUserParts }) {
  const useContext = Array.isArray(context.messages) && context.messages.length > 0;
  const useHistory = !useContext && Array.isArray(historyMessages) && historyMessages.length > 0;
  const baseMessages = useContext
    ? context.messages.map((message) => ({ role: message.role, parts: message.parts }))
    : (useHistory ? historyMessages : []);

  const maxMessages = CONTEXT_MAX_MESSAGES > 0 ? CONTEXT_MAX_MESSAGES : 0;
  const selected = maxMessages > 0 ? baseMessages.slice(-maxMessages) : baseMessages;
  return [
    ...selected,
    { role: "user", parts: currentUserParts },
  ];
}

function appendContextMessage(context, role, parts) {
  context.messages.push({ role, parts, createdAt: Date.now() });
  const maxMessages = CONTEXT_MAX_MESSAGES > 0 ? CONTEXT_MAX_MESSAGES : 0;
  if (maxMessages > 0 && context.messages.length > maxMessages) {
    context.messages.splice(0, context.messages.length - maxMessages);
  }
  context.updatedAt = Date.now();
}

function primeConversationContext(context, historyMessages) {
  if (Array.isArray(context.messages) && context.messages.length > 0) {
    return;
  }
  if (!Array.isArray(historyMessages) || historyMessages.length === 0) return;

  const maxMessages = CONTEXT_MAX_MESSAGES > 0 ? CONTEXT_MAX_MESSAGES : 0;
  const selected = maxMessages > 0 ? historyMessages.slice(-maxMessages) : historyMessages;
  context.messages = selected.map((message) => ({
    role: message.role,
    parts: message.parts,
    createdAt: Date.now(),
  }));
  context.updatedAt = Date.now();
}

async function generateReplyWithRetry({ model, contents, webSearch, timeoutMs }) {
  let lastError = null;

  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const config = {
        systemInstruction: RESPONSE_STYLE_INSTRUCTION,
      };
      if (webSearch) {
        config.tools = [{ googleSearch: {} }];
      }

      const response = await withTimeout(
        ai.models.generateContent({
          model,
          contents,
          config,
        }),
        timeoutMs
      );

      const reply = typeof response.text === "string" ? response.text.trim() : "";
      if (!reply) {
        throw new Error(`模型 ${model} 未返回有效文本`);
      }

      return { reply, model };
    } catch (error) {
      lastError = error;
      const shouldRetry = attempt < 2 && isTransientError(error);
      if (shouldRetry) {
        await delay(400);
        continue;
      }
      break;
    }
  }

  throw lastError || new Error("模型未返回可用结果");
}

async function handleChat(req, res) {
  const rawMessage = req.body?.message ?? req.body?.question;
  const userMessage = typeof rawMessage === "string" ? rawMessage.trim() : "";
  const attachments = normalizeAttachments(req.body?.attachments);
  const requestedModel = req.body?.model;
  const modelResult = resolveRequestModel(requestedModel);
  const conversationId = normalizeConversationId(req.body?.conversationId);
  const historyMessages = normalizeConversationHistory(req.body?.history);
  const forceWebSearch = shouldForceWebSearchByQuestion(userMessage);
  const useWebSearch = Boolean(req.body?.webSearch) || forceWebSearch;

  if (!userMessage && attachments.length === 0) {
    return res.status(400).json({
      success: false,
      message: "问题和附件不能同时为空",
    });
  }

  if (!process.env.GEMINI_API_KEY) {
    return res.status(500).json({
      success: false,
      message: "服务端未配置 GEMINI_API_KEY",
    });
  }

  if (!modelResult.ok) {
    return res.status(400).json({
      success: false,
      errorCode: "UPSTREAM_MODEL_NOT_AVAILABLE",
      message: "请求模型不受支持，请切换为可用模型后重试",
      error: `unsupported model: ${normalizeModelValue(requestedModel) || "(empty)"}`,
    });
  }

  const activeModel = modelResult.model;
  const timeoutMs = resolveRequestTimeoutMs({
    requestedTimeoutMs: req.body?.timeoutMs,
    userMessage,
    useWebSearch,
    model: activeModel,
  });
  const context = getConversationContext(req.authUser.id, conversationId);
  primeConversationContext(context, historyMessages);
  const currentUserParts = buildUserParts(userMessage, attachments);
  const contents = buildConversationContents({
    context,
    historyMessages,
    currentUserParts,
  });

  try {
    console.log(
      "收到前端提问：",
      userMessage || "（无文本问题）",
      "附件数：",
      attachments.length,
      "用户：",
      req.authUser.id,
      "会话：",
      conversationId,
      "请求模型：",
      normalizeModelValue(requestedModel) || "(default)",
      "实际模型：",
      activeModel,
      "超时阈值(ms)：",
      timeoutMs,
      "联网检索：",
      useWebSearch,
      "强制检索：",
      forceWebSearch
    );

    const { reply, model } = await generateReplyWithRetry({
      model: activeModel,
      contents,
      webSearch: useWebSearch,
      timeoutMs,
    });

    appendContextMessage(context, "user", currentUserParts);
    appendContextMessage(context, "model", [{ text: reply }]);

    return res.json({
      success: true,
      reply,
      model,
      attachmentCount: attachments.length,
      conversationId,
    });
  } catch (error) {
    const mappedError = mapUpstreamError(error);
    console.error(
      "模型调用出错:",
      `user=${req.authUser.id}`,
      `conversation=${conversationId}`,
      `model=${activeModel}`,
      `code=${mappedError.errorCode}`,
      `status=${mappedError.statusCode}`,
      mappedError.detail
    );
    return res.status(mappedError.statusCode).json({
      success: false,
      errorCode: mappedError.errorCode,
      message: mappedError.userMessage,
      error: mappedError.detail,
    });
  }
}

function createInMemoryRateLimiter({ windowMs, maxRequests }) {
  const ipHits = new Map();

  setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of ipHits.entries()) {
      if (record.resetAt <= now) {
        ipHits.delete(ip);
      }
    }
  }, Math.max(5_000, Math.floor(windowMs / 2))).unref();

  return (req, res, next) => {
    const now = Date.now();
    const ip = req.ip || req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
    const existing = ipHits.get(ip);

    if (!existing || existing.resetAt <= now) {
      ipHits.set(ip, { count: 1, resetAt: now + windowMs });
      setRateLimitHeaders(res, maxRequests, maxRequests - 1, now + windowMs);
      next();
      return;
    }

    if (existing.count >= maxRequests) {
      const retryAfterSeconds = Math.max(1, Math.ceil((existing.resetAt - now) / 1000));
      setRateLimitHeaders(res, maxRequests, 0, existing.resetAt);
      res.setHeader("Retry-After", retryAfterSeconds);
      res.status(429).json({
        success: false,
        message: `请求过于频繁，请在 ${retryAfterSeconds} 秒后重试`,
      });
      return;
    }

    existing.count += 1;
    setRateLimitHeaders(res, maxRequests, Math.max(0, maxRequests - existing.count), existing.resetAt);
    next();
  };
}

function setRateLimitHeaders(res, limit, remaining, resetAt) {
  res.setHeader("X-RateLimit-Limit", String(limit));
  res.setHeader("X-RateLimit-Remaining", String(remaining));
  res.setHeader("X-RateLimit-Reset", String(Math.ceil(resetAt / 1000)));
}

app.listen(PORT, () => {
  console.log("✅ 汉盛智能后端服务器已成功启动！");
  console.log(`👉 监听地址：http://localhost:${PORT}`);
  console.log(`👉 默认模型：${DEFAULT_MODEL}`);
  console.log(`👉 可选模型：${ALLOWED_MODELS.join(", ")}`);
  console.log(`👉 上下文记忆条数：${CONTEXT_MAX_MESSAGES > 0 ? CONTEXT_MAX_MESSAGES : "不限制"}`);
  console.log(`👉 上下文保留时长：${Math.round(CONTEXT_TTL_MS / 1000 / 60)} 分钟`);
  console.log(`👉 运行环境：${NODE_ENV}`);
  console.log(`👉 接口限流：${RATE_LIMIT_MAX_REQUESTS}次/${Math.round(RATE_LIMIT_WINDOW_MS / 1000)}秒`);
});
