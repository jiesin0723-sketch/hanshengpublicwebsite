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
  "gemini-3.1-pro-preview",
  "gemini-3-pro-preview",
  "gemini-2.5-flash",
  "gemini-2.5-pro",
  "gemma-3-1b-it",
  "gemma-3-4b-it",
];
const RESERVED_PAID_MODELS = parseModelList(process.env.GEMINI_RESERVED_MODELS || "", []);
const ENV_DEFAULT_MODEL = (process.env.GEMINI_MODEL || "gemini-3.1-pro-preview").trim();
const ALLOWED_MODELS = [
  ...new Set([
    ...parseModelList(process.env.GEMINI_ALLOWED_MODELS || "", DEFAULT_ALLOWED_MODELS),
    ...RESERVED_PAID_MODELS,
  ]),
];
const SUPPORTED_MODELS = new Set(ALLOWED_MODELS);
const DEFAULT_MODEL = SUPPORTED_MODELS.has(ENV_DEFAULT_MODEL)
  ? ENV_DEFAULT_MODEL
  : ALLOWED_MODELS[0] || "gemini-3.1-pro-preview";

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
【角色定位】
你是一位拥有十余年实务经验的中国大陆资深商事与金融诉讼律师及仲裁员。你的受众是极其专业的合伙人级别律师，你的回答必须摒弃一切废话与客套，直击法律实质。

【工作流与分析逻辑 (强制执行 IRAC 原则)】
在面对复杂的合同、侵权竞合或刑事合规问题时，你必须严格按照以下结构输出：
1. **案件拆解与检索策略 (Plan)**：简要列出你为了回答此问题，需要核实的 1-3 个核心法律冲突及对应的底层法规/类案检索方向。
2. **争议焦点 (Issue)**：精准提炼案件的核心法律冲突。
3. **裁判规则与法理 (Rule)**：引用具体、现行有效的中国法律法规、司法解释或最高人民法院的指导性案例/公报案例。必须带有具体条文序号和生效年份。
4. **事实适用 (Application)**：将案件事实代入上述规则，进行严密的逻辑推演。若有附件，必须优先引用附件原文。
5. **实务结论与风险暴露 (Conclusion)**：给出清晰的倾向性结论，并务必提示诉讼/仲裁的举证风险或商业不确定性。

【不可逾越的红线】
1. **严禁捏造 (Zero Hallucination)**：绝对不允许编造不存在的法条、案号或法院判决。如果你不确定，必须明确回答“现有检索未发现明确依据”。
2. **强制实证**：引用网络资料、最新法规或案例时，必须在对应句末使用 Markdown 超链接标注原文来源。
3. **排除非中国大陆法**：除非特别指令，否则禁止引用英美法系规则，必须立足于中国本土司法实践。
`;

const MODEL_SAMPLING_CONFIG = {
  temperature: 0.1,
  topP: 0.8,
  topK: 40,
};

const PLAN_AND_SOLVE_PROMPT = `
你当前处于 Pass 1（策略生成层），禁止调用联网工具。
请基于用户问题与已给出的历史/附件信息，完成以下任务并仅输出 JSON：
{
  "plan": ["最多 3 条，描述要核实的法律冲突与检索方向"],
  "issue": "一句话提炼核心争议焦点",
  "searchQueries": ["3-4 条可直接用于 Google 的检索关键词，必须具体可执行"]
}
要求：
1) searchQueries 必须是中文或中英混合专业检索词，禁止空泛表达；
2) 若信息不足，需在 plan 中写明“待补充事实”；
3) 不要输出 JSON 之外的任何内容。
`;

const PLAN_AND_SOLVE_FINAL_PROMPT = `
请仔细阅读前置的检索策略，系统现已为你开启联网权限。
请针对这些拆解出的关键词进行深度搜索，交叉比对后，输出最终的 IRAC 法律意见书。
强制要求：
1) 结论必须可追溯到中国大陆现行有效法律法规、司法解释、指导性案例或公报案例；
2) 每个关键外部依据必须在句末添加 Markdown 超链接；
3) 若附件事实不足或证据链存在断裂，必须明确写出举证风险；
4) 不得编造法条、案号或裁判观点。
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
  const causeCode = String(error?.cause?.code || "").trim();
  const causeMessage = String(error?.cause?.message || "").trim();
  const enriched = [message, causeCode, causeMessage].filter(Boolean).join(" | ");
  const full = enriched || message;
  return full.length > 500 ? `${full.slice(0, 500)}...` : full;
}

function isNetworkError(error) {
  const message = normalizeErrorMessage(error).toLowerCase();
  return (
    message.includes("fetch failed") ||
    message.includes("und_err_socket") ||
    message.includes("socketerror") ||
    message.includes("other side closed") ||
    message.includes("econnreset") ||
    message.includes("econnrefused") ||
    message.includes("network") ||
    message.includes("proxy")
  );
}

function isTransientError(error) {
  const raw = normalizeErrorMessage(error);
  const message = raw.toLowerCase();
  return (
    message.includes("timeout") ||
    message.includes("timed out") ||
    message.includes("503") ||
    message.includes("temporarily") ||
    message.includes("unavailable") ||
    message.includes("etimedout") ||
    raw.includes("超时") ||
    isNetworkError(error)
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

function buildGenerationConfig({ webSearch }) {
  const config = {
    systemInstruction: RESPONSE_STYLE_INSTRUCTION,
    ...MODEL_SAMPLING_CONFIG,
  };
  if (webSearch) {
    config.tools = [{ googleSearch: {} }];
  }
  return config;
}

function parsePlanAndSolvePayload(rawText) {
  const text = String(rawText || "").trim();
  if (!text) return null;

  const candidates = [text];
  const fencedMatches = text.match(/```(?:json)?\s*([\s\S]*?)```/gi) || [];
  for (const block of fencedMatches) {
    const stripped = block.replace(/```(?:json)?/i, "").replace(/```$/, "").trim();
    if (stripped) candidates.push(stripped);
  }

  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === "object") return parsed;
    } catch {
      continue;
    }
  }
  return null;
}

function extractSearchQueries(rawText, userMessage) {
  const parsed = parsePlanAndSolvePayload(rawText);
  let queries = [];

  if (parsed && Array.isArray(parsed.searchQueries)) {
    queries = parsed.searchQueries;
  } else {
    const lines = String(rawText || "").split(/\r?\n/);
    for (const line of lines) {
      const cleaned = line
        .replace(/^\s*[-*•]\s*/, "")
        .replace(/^\s*\d+[.)、]\s*/, "")
        .trim();
      if (cleaned.length >= 8) {
        queries.push(cleaned);
      }
    }
  }

  const normalized = [...new Set(queries.map((item) => String(item || "").trim()).filter(Boolean))].slice(0, 4);
  if (normalized.length >= 3) return normalized;

  const topic = String(userMessage || "").replace(/\s+/g, " ").trim().slice(0, 32) || "争议事项";
  const fallback = [
    `${topic} 最高人民法院 指导性案例`,
    `${topic} 民法典 司法解释`,
    `${topic} 裁判文书 责任认定`,
  ];
  return [...new Set([...normalized, ...fallback])].slice(0, 4);
}

function buildPlanPassContents(contents) {
  return [
    ...contents,
    { role: "user", parts: [{ text: PLAN_AND_SOLVE_PROMPT }] },
  ];
}

function buildFinalPassContents({ contents, strategyText, searchQueries }) {
  const queryBlock = searchQueries.map((item, index) => `${index + 1}. ${item}`).join("\n");
  const contextText = [
    "【Pass 1 检索策略原文】",
    strategyText || "（无）",
    "",
    "【建议检索关键词】",
    queryBlock || "1. 中国法律法规 官方来源 核验",
    "",
    "【Pass 2 指令】",
    PLAN_AND_SOLVE_FINAL_PROMPT,
  ].join("\n");

  return [
    ...contents,
    { role: "user", parts: [{ text: contextText }] },
  ];
}

function shouldUsePlanAndSolvePipeline({ webSearch, timeoutMs }) {
  return Boolean(webSearch) || Number(timeoutMs) >= COMPLEX_QUESTION_MIN_TIMEOUT_MS;
}

async function callGenerateOnce({ model, contents, webSearch, timeoutMs }) {
  const response = await withTimeout(
    ai.models.generateContent({
      model,
      contents,
      config: buildGenerationConfig({ webSearch }),
    }),
    timeoutMs
  );

  const reply = typeof response.text === "string" ? response.text.trim() : "";
  if (!reply) {
    throw new Error(`模型 ${model} 未返回有效文本`);
  }
  return reply;
}

async function runTwoPassPlanAndSolve({ model, contents, timeoutMs, userMessage }) {
  const pass1Timeout = Math.max(
    MIN_REQUEST_TIMEOUT_MS,
    Math.min(MAX_REQUEST_TIMEOUT_MS, Math.floor(timeoutMs * 0.45))
  );
  const strategyText = await callGenerateOnce({
    model,
    contents: buildPlanPassContents(contents),
    webSearch: false,
    timeoutMs: pass1Timeout,
  });
  const searchQueries = extractSearchQueries(strategyText, userMessage);
  const finalReply = await callGenerateOnce({
    model,
    contents: buildFinalPassContents({
      contents,
      strategyText,
      searchQueries,
    }),
    webSearch: true,
    timeoutMs,
  });
  return {
    reply: finalReply,
    model,
    webSearchUsed: true,
    pipeline: "TWO_PASS_PLAN_AND_SOLVE",
    searchQueries,
  };
}

async function generateReplyWithRetry({ model, contents, webSearch, timeoutMs, userMessage }) {
  let lastError = null;
  const maxAttempts = 3;
  const usePlanAndSolve = shouldUsePlanAndSolvePipeline({ webSearch, timeoutMs });
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      if (usePlanAndSolve) {
        return await runTwoPassPlanAndSolve({
          model,
          contents,
          timeoutMs,
          userMessage,
        });
      }
      const reply = await callGenerateOnce({ model, contents, webSearch, timeoutMs });
      return {
        reply,
        model,
        webSearchUsed: webSearch,
        pipeline: "SINGLE_PASS",
        searchQueries: [],
      };
    } catch (error) {
      lastError = error;
      const shouldRetry = attempt < maxAttempts && isTransientError(error);
      if (shouldRetry) {
        await delay(500 * attempt);
        continue;
      }
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
    const generationResult = await generateReplyWithRetry({
      model: activeModel,
      contents,
      webSearch: useWebSearch,
      timeoutMs,
      userMessage,
    });

    console.log(
      "收到前端提问：",
      userMessage || "（无文本问题）",
      "附件数：",
      attachments.length,
      "用户：",
      req.authUser.id,
      "会话：",
      conversationId,
      "超时阈值(ms)：",
      timeoutMs,
      "强制检索：",
      forceWebSearch,
      `请求模型：${normalizeModelValue(requestedModel) || "(default)"}`,
      `实际模型：${generationResult.model}`,
      `联网检索：${generationResult.webSearchUsed}`,
      `推理管线：${generationResult.pipeline}`,
      `检索词数：${Array.isArray(generationResult.searchQueries) ? generationResult.searchQueries.length : 0}`
    );

    appendContextMessage(context, "user", currentUserParts);
    appendContextMessage(context, "model", [{ text: generationResult.reply }]);

    return res.json({
      success: true,
      reply: generationResult.reply,
      model: generationResult.model,
      attachmentCount: attachments.length,
      conversationId,
      webSearchUsed: generationResult.webSearchUsed,
      pipeline: generationResult.pipeline,
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
