require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const { GoogleGenAI } = require("@google/genai");

const app = express();
const NODE_ENV = process.env.NODE_ENV || "development";
const PORT = readPositiveInt("PORT", 3000);
const DEFAULT_MODEL = "gemini-2.5-pro";
const MODEL = process.env.GEMINI_MODEL || DEFAULT_MODEL;
const REQUEST_TIMEOUT_MS = readPositiveInt("REQUEST_TIMEOUT_MS", 25000);
const MAX_ATTACHMENTS = readPositiveInt("MAX_ATTACHMENTS", 4);
const MAX_TEXT_ATTACHMENT_CHARS = readPositiveInt("MAX_TEXT_ATTACHMENT_CHARS", 120000);
const MAX_BASE64_ATTACHMENT_CHARS = readPositiveInt("MAX_BASE64_ATTACHMENT_CHARS", 8_000_000);
const RATE_LIMIT_WINDOW_MS = readPositiveInt("RATE_LIMIT_WINDOW_MS", 60_000);
const RATE_LIMIT_MAX_REQUESTS = readPositiveInt("RATE_LIMIT_MAX_REQUESTS", 20);
const TRUST_PROXY = process.env.TRUST_PROXY || "1";
const ALLOWED_CORS_ORIGINS = parseCorsOrigins(process.env.CORS_ORIGINS || "");
const SUPPORTED_BINARY_MIME_TYPES = new Set([
  "application/pdf",
  "image/png",
  "image/jpeg",
  "image/webp",
]);
const SUPPORTED_MODELS = new Set(["gemini-2.5-pro", "gemini-2.5-flash"]);
const RESPONSE_STYLE_INSTRUCTION =
  "请使用中文回答，并严格按易读格式输出：1) 先给2-5行结论；2) 再用小标题分段；3) 每段用短句和项目符号；4) 不要输出一整段长文本；5) 关键点之间保留空行。";

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
app.use(express.json({ limit: "20mb" }));
app.use(express.static(path.join(__dirname)));

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});
const chatRateLimiter = createInMemoryRateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  maxRequests: RATE_LIMIT_MAX_REQUESTS,
});

app.get("/health", (_req, res) => {
  res.json({ success: true, message: "ok" });
});

app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

function readPositiveInt(name, fallback) {
  const value = Number(process.env[name]);
  if (Number.isFinite(value) && value > 0) {
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

function normalizeModelValue(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  return raw;
}

function resolveRequestModel(requestModel) {
  const normalizedRequested = normalizeModelValue(requestModel);
  if (normalizedRequested) {
    if (!SUPPORTED_MODELS.has(normalizedRequested)) {
      return { ok: false, model: "", reason: "UNSUPPORTED_MODEL" };
    }
    return { ok: true, model: normalizedRequested, reason: "" };
  }

  const normalizedDefault = normalizeModelValue(MODEL) || DEFAULT_MODEL;
  if (!SUPPORTED_MODELS.has(normalizedDefault)) {
    return { ok: true, model: DEFAULT_MODEL, reason: "FALLBACK_DEFAULT_MODEL" };
  }
  return { ok: true, model: normalizedDefault, reason: "" };
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function withTimeout(promise, timeoutMs) {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`Gemini 请求超时（>${timeoutMs}ms）`)), timeoutMs);
    }),
  ]);
}

function normalizeErrorMessage(error) {
  const message = String(error?.message || "unknown error");
  return message.length > 500 ? `${message.slice(0, 500)}...` : message;
}

function isTransientError(error) {
  const msg = normalizeErrorMessage(error).toLowerCase();
  return (
    msg.includes("timeout") ||
    msg.includes("timed out") ||
    msg.includes("503") ||
    msg.includes("temporarily") ||
    msg.includes("unavailable") ||
    msg.includes("econnreset") ||
    msg.includes("etimedout")
  );
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
      userMessage: "当前模型配额不足，请切换到 Gemini 2.5 Flash 或稍后重试",
      detail: payload?.message || raw,
    };
  }

  if (
    payload?.code === 404 ||
    payload?.status === "NOT_FOUND" ||
    payloadMessage.includes("is not found for api version") ||
    lower.includes("model") && lower.includes("not found")
  ) {
    return {
      statusCode: 502,
      errorCode: "UPSTREAM_MODEL_NOT_AVAILABLE",
      userMessage: "当前模型不可用，请切换模型后重试",
      detail: payload?.message || raw,
    };
  }

  if (lower.includes("timeout") || lower.includes("timed out") || lower.includes("aborted")) {
    return {
      statusCode: 504,
      errorCode: "UPSTREAM_TIMEOUT",
      userMessage: "请求 Gemini 超时，请稍后重试",
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
      userMessage: "后端到 Gemini 网络请求失败，请检查网络与 HTTPS_PROXY 配置",
      detail: payload?.message || raw,
    };
  }

  return {
    statusCode: 500,
    errorCode: "UNKNOWN_UPSTREAM_ERROR",
    userMessage: "Gemini 调用失败，请稍后重试",
    detail: payload?.message || raw,
  };
}

function normalizeFilename(name, fallbackName) {
  const raw = typeof name === "string" ? name.trim() : "";
  if (!raw) {
    return fallbackName;
  }
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

async function generateReplyWithRetry(userMessage, attachments, model) {
  let lastError = null;
  const parts = buildUserParts(userMessage, attachments);

  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const response = await withTimeout(
        ai.models.generateContent({
          model,
          contents: [
            {
              role: "user",
              parts,
            },
          ],
          config: {
            systemInstruction: RESPONSE_STYLE_INSTRUCTION,
          },
        }),
        REQUEST_TIMEOUT_MS
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

  throw lastError || new Error("Gemini 未返回可用结果");
}

async function handleChat(req, res) {
  const rawMessage = req.body?.message ?? req.body?.question;
  const userMessage = typeof rawMessage === "string" ? rawMessage.trim() : "";
  const attachments = normalizeAttachments(req.body?.attachments);
  const requestedModel = req.body?.model;
  const modelResult = resolveRequestModel(requestedModel);

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
      message: "请求模型不受支持，请切换到 Gemini 2.5 Pro 或 Gemini 2.5 Flash",
      error: `unsupported model: ${normalizeModelValue(requestedModel) || "(empty)"}`,
    });
  }

  const activeModel = modelResult.model;
  if (modelResult.reason === "FALLBACK_DEFAULT_MODEL") {
    console.warn(
      `[MODEL] GEMINI_MODEL "${MODEL}" 不在白名单中，已回退为 ${activeModel}`
    );
  }

  try {
    console.log(
      "收到前端提问：",
      userMessage || "（无文本问题）",
      "附件数：",
      attachments.length,
      "请求模型：",
      normalizeModelValue(requestedModel) || "(default)",
      "实际模型：",
      activeModel
    );
    const { reply, model } = await generateReplyWithRetry(userMessage, attachments, activeModel);

    return res.json({
      success: true,
      reply,
      model,
      attachmentCount: attachments.length,
    });
  } catch (error) {
    const mappedError = mapUpstreamError(error);
    console.error(
      "Gemini 引擎调用出错:",
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

app.post("/api/chat", chatRateLimiter, handleChat);
app.post("/ask", chatRateLimiter, handleChat);

app.listen(PORT, () => {
  console.log("✅ 汉盛智能后端服务器已成功启动！");
  console.log(`👉 监听地址：http://localhost:${PORT}`);
  console.log(`👉 Gemini 模型：${MODEL}`);
  console.log(`👉 运行环境：${NODE_ENV}`);
  console.log(`👉 接口限流：${RATE_LIMIT_MAX_REQUESTS}次/${Math.round(RATE_LIMIT_WINDOW_MS / 1000)}秒`);
});
