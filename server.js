require("dotenv").config();
const crypto = require("crypto");
const fs = require("fs");
const fsp = require("fs/promises");
const express = require("express");
const cors = require("cors");
const path = require("path");
const multer = require("multer");
const OSS = require("ali-oss");
const OpenApi = require("@alicloud/openapi-client");
const AlibabaCloudSts = require("@alicloud/sts20150401");
const AlibabaCloudDocMind = require("@alicloud/docmind-api20220711");
const TeaUtil = require("@alicloud/tea-util");
const mammoth = require("mammoth");
const XLSX = require("xlsx");
const WordExtractor = require("word-extractor");
const pdfParse = require("pdf-parse");
const { once } = require("events");
const { GoogleGenAI } = require("@google/genai");

const app = express();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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

function readBool(name, fallback) {
  const raw = String(process.env[name] || "").trim().toLowerCase();
  if (!raw) return fallback;
  if (["1", "true", "yes", "y", "on"].includes(raw)) return true;
  if (["0", "false", "no", "n", "off"].includes(raw)) return false;
  return fallback;
}

function parseCorsOrigins(rawOrigins) {
  return String(rawOrigins)
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function matchCorsOriginByWildcard(origin, pattern) {
  if (!origin || !pattern || !pattern.includes("*")) return false;
  const escaped = pattern
    .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*");
  const regex = new RegExp(`^${escaped}$`, "i");
  return regex.test(origin);
}

function isCorsOriginAllowed(origin, allowList) {
  if (!origin) return true;
  if (!Array.isArray(allowList) || allowList.length === 0) return true;
  if (allowList.includes("*")) return true;
  if (allowList.includes(origin)) return true;
  return allowList.some((pattern) => matchCorsOriginByWildcard(origin, pattern));
}

function normalizeHost(value) {
  return String(value || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/+$/g, "");
}

function detectOssRegion() {
  const host = normalizeHost(OSS_ENDPOINT);
  const match = host.match(/(oss-[a-z0-9-]+)/i);
  return match ? match[1].toLowerCase() : "";
}

function hasOssCredentials() {
  return Boolean(OSS_ENABLED && OSS_BUCKET && OSS_ENDPOINT && OSS_ACCESS_KEY_ID && OSS_ACCESS_KEY_SECRET);
}

function getOssHost() {
  const endpointHost = normalizeHost(OSS_ENDPOINT);
  if (!endpointHost) return "";
  if (endpointHost.startsWith(`${OSS_BUCKET}.`)) return endpointHost;
  return `${OSS_BUCKET}.${endpointHost}`;
}

function getOssUploadBaseUrl() {
  const host = getOssHost();
  if (!host) return "";
  return `${OSS_FORCE_HTTPS ? "https" : "http"}://${host}`;
}

function encodeOssObjectKey(key) {
  return String(key || "")
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
}

function sanitizeObjectName(name) {
  return String(name || "file")
    .trim()
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 120) || "file";
}

function buildOssObjectKey({ userId, conversationId, fileName }) {
  const safeUserId = sanitizeObjectName(userId || "unknown");
  const safeConversationId = sanitizeObjectName(conversationId || "default");
  const safeFileName = sanitizeObjectName(fileName || "file");
  const randomHex = crypto.randomBytes(6).toString("hex");
  return `${OSS_OBJECT_PREFIX}/${safeUserId}/${safeConversationId}/${Date.now()}_${randomHex}_${safeFileName}`;
}

function signOssPolicyBase64(policyBase64) {
  return crypto.createHmac("sha1", OSS_ACCESS_KEY_SECRET).update(policyBase64).digest("base64");
}

function buildSignedOssGetUrl(objectKey, expireSeconds = 300) {
  const host = getOssHost();
  if (!host) return "";
  const expires = Math.floor(Date.now() / 1000) + Math.max(60, expireSeconds);
  const canonicalResource = `/${OSS_BUCKET}/${String(objectKey || "").replace(/^\/+/, "")}`;
  const stringToSign = `GET\n\n\n${expires}\n${canonicalResource}`;
  const signature = crypto
    .createHmac("sha1", OSS_ACCESS_KEY_SECRET)
    .update(stringToSign)
    .digest("base64");
  const base = `${OSS_FORCE_HTTPS ? "https" : "http"}://${host}/${encodeOssObjectKey(objectKey)}`;
  const query = new URLSearchParams({
    OSSAccessKeyId: OSS_ACCESS_KEY_ID,
    Expires: String(expires),
    Signature: signature,
  });
  return `${base}?${query.toString()}`;
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
const PORT = readPositiveInt("PORT", 10000);
const HOST = "0.0.0.0";
const REQUEST_TIMEOUT_MS = readPositiveInt("REQUEST_TIMEOUT_MS", 90_000);
const MIN_REQUEST_TIMEOUT_MS = readPositiveInt("MIN_REQUEST_TIMEOUT_MS", 20_000);
const MAX_REQUEST_TIMEOUT_MS = readPositiveInt("MAX_REQUEST_TIMEOUT_MS", 300_000);
const WEB_SEARCH_MIN_TIMEOUT_MS = readPositiveInt("WEB_SEARCH_MIN_TIMEOUT_MS", 90_000);
const COMPLEX_QUESTION_MIN_TIMEOUT_MS = readPositiveInt("COMPLEX_QUESTION_MIN_TIMEOUT_MS", 120_000);
const COMPLEX_QUESTION_CHAR_THRESHOLD = readPositiveInt("COMPLEX_QUESTION_CHAR_THRESHOLD", 220);
const MAX_ATTACHMENTS = readPositiveInt("MAX_ATTACHMENTS", 15);
const MAX_BINARY_ATTACHMENT_BYTES = readPositiveInt("MAX_BINARY_ATTACHMENT_BYTES", 100 * 1024 * 1024);
const MAX_BASE64_ATTACHMENT_CHARS = readPositiveInt(
  "MAX_BASE64_ATTACHMENT_CHARS",
  Math.ceil((MAX_BINARY_ATTACHMENT_BYTES / 3) * 4) + 8
);
const MAX_TEXT_ATTACHMENT_CHARS = readPositiveInt("MAX_TEXT_ATTACHMENT_CHARS", 120_000);
const FINANCIAL_DATA_MAX_CHARS = readPositiveInt("FINANCIAL_DATA_MAX_CHARS", 500_000);
const FINANCIAL_SUMMARY_TRIGGER_CHARS = readPositiveInt("FINANCIAL_SUMMARY_TRIGGER_CHARS", 120_000);
const FINANCIAL_SUMMARY_CHUNK_SIZE = readPositiveInt("FINANCIAL_SUMMARY_CHUNK_SIZE", 180);
const FINANCIAL_DETAIL_KEEP_ROWS = readPositiveInt("FINANCIAL_DETAIL_KEEP_ROWS", 240);
const JSON_BODY_LIMIT_MB = readPositiveInt("JSON_BODY_LIMIT_MB", 220);
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
const UPLOAD_ATTACHMENT_TTL_MS = readPositiveInt("UPLOAD_ATTACHMENT_TTL_MS", 24 * 60 * 60 * 1000);
const TEXT_EXTRACT_MAX_CHARS = readPositiveInt("TEXT_EXTRACT_MAX_CHARS", 300_000);
const LARGE_PDF_PARSE_THRESHOLD_BYTES = readPositiveInt("LARGE_PDF_PARSE_THRESHOLD_BYTES", 8 * 1024 * 1024);
const URL_ONLY_DOC_PARSE_THRESHOLD_BYTES = readPositiveInt("URL_ONLY_DOC_PARSE_THRESHOLD_BYTES", 2 * 1024 * 1024);
const OCR_PDF_MIN_TEXT_CHARS = readPositiveInt("OCR_PDF_MIN_TEXT_CHARS", 200);
const ASYNC_ATTACHMENT_CONTEXT_CHARS = readPositiveInt("ASYNC_ATTACHMENT_CONTEXT_CHARS", 120_000);
const DOCMIND_HTTP_TIMEOUT_MS = readPositiveInt("DOCMIND_HTTP_TIMEOUT_MS", 120_000);
const DOCMIND_POLL_INTERVAL_MS = readPositiveInt("DOCMIND_POLL_INTERVAL_MS", 3_000);
const DOCMIND_POLL_TIMEOUT_MS = readPositiveInt("DOCMIND_POLL_TIMEOUT_MS", 15 * 60 * 1000);
const DOCMIND_POLL_MAX_ATTEMPTS = readPositiveInt(
  "DOCMIND_POLL_MAX_ATTEMPTS",
  Math.max(100, Math.ceil(DOCMIND_POLL_TIMEOUT_MS / DOCMIND_POLL_INTERVAL_MS))
);
const DOCMIND_TIMEOUT_RETRY_DELAY_MS = readPositiveInt("DOCMIND_TIMEOUT_RETRY_DELAY_MS", 15_000);
const DOCMIND_TIMEOUT_RETRY_LIMIT = readPositiveInt("DOCMIND_TIMEOUT_RETRY_LIMIT", 6);
const OSS_ENABLED = readBool("OSS_ENABLED", true);
const OSS_BUCKET = String(process.env.OSS_BUCKET || "").trim();
const OSS_ENDPOINT = String(process.env.OSS_ENDPOINT || "").trim();
const OSS_ACCESS_KEY_ID = String(process.env.OSS_ACCESS_KEY_ID || "").trim();
const OSS_ACCESS_KEY_SECRET = String(process.env.OSS_ACCESS_KEY_SECRET || "").trim();
const OSS_OBJECT_PREFIX = String(process.env.OSS_OBJECT_PREFIX || "uploads").trim() || "uploads";
const OSS_PRESIGN_EXPIRE_SECONDS = readPositiveInt("OSS_PRESIGN_EXPIRE_SECONDS", 600);
const OSS_FETCH_TIMEOUT_MS = readPositiveInt("OSS_FETCH_TIMEOUT_MS", 180_000);
const OSS_FORCE_HTTPS = readBool("OSS_FORCE_HTTPS", true);
const OSS_PUBLIC_BASE_URL = String(process.env.OSS_PUBLIC_BASE_URL || "").trim();
const OSS_UPLOAD_METHOD = ["PUT", "POST"].includes(String(process.env.OSS_UPLOAD_METHOD || "PUT").trim().toUpperCase())
  ? String(process.env.OSS_UPLOAD_METHOD || "PUT").trim().toUpperCase()
  : "PUT";
const OSS_STS_ENABLED = readBool("OSS_STS_ENABLED", true);
const OSS_STS_ROLE_ARN = String(process.env.OSS_STS_ROLE_ARN || "").trim();
const OSS_STS_EXTERNAL_ID = String(process.env.OSS_STS_EXTERNAL_ID || "").trim();
const OSS_STS_REGION_ID = String(process.env.OSS_STS_REGION_ID || "cn-hangzhou").trim();
const OSS_STS_ENDPOINT = String(process.env.OSS_STS_ENDPOINT || "sts.aliyuncs.com").trim();
const OSS_STS_DURATION_SECONDS = readPositiveInt("OSS_STS_DURATION_SECONDS", 3600);
const OSS_STS_SESSION_PREFIX = String(process.env.OSS_STS_SESSION_PREFIX || "hansheng-upload").trim();
const OSS_MULTIPART_PART_SIZE_BYTES = readPositiveInt("OSS_MULTIPART_PART_SIZE_BYTES", 2 * 1024 * 1024);
const OSS_MULTIPART_PARALLEL = readPositiveInt("OSS_MULTIPART_PARALLEL", 3);
const DOCMIND_ENDPOINT = "docmind-api.cn-hangzhou.aliyuncs.com";
const DOCMIND_REGION_ID = String(process.env.DOCMIND_REGION_ID || process.env.OCR_REGION_ID || "cn-hangzhou").trim();
const OSS_SIGNED_URL_EXPIRE_SECONDS = readPositiveInt("OSS_SIGNED_URL_EXPIRE_SECONDS", 3600);
const OSS_REGION = String(process.env.OSS_REGION || detectOssRegion()).trim();
const ATTACHMENT_PARSE_BASE_ETA_MS = readPositiveInt("ATTACHMENT_PARSE_BASE_ETA_MS", 180_000);
const ATTACHMENT_PARSE_MAX_ETA_MS = readPositiveInt("ATTACHMENT_PARSE_MAX_ETA_MS", 20 * 60 * 1000);
const ATTACHMENT_JOB_MAX_QUEUE = readPositiveInt("ATTACHMENT_JOB_MAX_QUEUE", 200);
const ATTACHMENT_JOB_MAX_RETRIES = readNonNegativeInt("ATTACHMENT_JOB_MAX_RETRIES", 2);
const ATTACHMENT_JOB_TTL_MS = readPositiveInt("ATTACHMENT_JOB_TTL_MS", 24 * 60 * 60 * 1000);
const GEMINI_PDF_MAX_BYTES = readPositiveInt("GEMINI_PDF_MAX_BYTES", 50 * 1024 * 1024);
const GEMINI_FILE_ACTIVE_POLL_MS = readPositiveInt("GEMINI_FILE_ACTIVE_POLL_MS", 2_000);
const GEMINI_FILE_ACTIVE_TIMEOUT_MS = readPositiveInt("GEMINI_FILE_ACTIVE_TIMEOUT_MS", 120_000);
const GEMINI_ATTACHMENT_SUMMARY_TIMEOUT_MS = readPositiveInt("GEMINI_ATTACHMENT_SUMMARY_TIMEOUT_MS", 180_000);
const SPLIT_WORKER_URL = String(process.env.SPLIT_WORKER_URL || "").trim();
const SPLIT_WORKER_TOKEN = String(process.env.SPLIT_WORKER_TOKEN || "").trim();
const SPLIT_WORKER_TIMEOUT_MS = readPositiveInt("SPLIT_WORKER_TIMEOUT_MS", 180_000);
const SPLIT_WORKER_PART_MAX_BYTES = readPositiveInt("SPLIT_WORKER_PART_MAX_BYTES", 35 * 1024 * 1024);
const SPLIT_WORKER_MAX_RETRIES = readNonNegativeInt("SPLIT_WORKER_MAX_RETRIES", 2);

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
const WORD_MIME_TYPES = new Set([
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
]);
const EXCEL_MIME_TYPES = new Set([
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
]);
const PDF_IMAGE_MIME_TYPES = new Set([
  "application/pdf",
  "image/png",
  "image/jpeg",
  "image/webp",
]);
const TEXT_MIME_TYPES = new Set([
  "text/plain",
  "text/markdown",
  "text/csv",
  "application/json",
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
【核心角色定位】
你是一位顶尖的商事犯罪辩护律师兼高级数据分析专家。你的任务是协助主审律师分析案件材料，尤其是合同、证据链和资金流水，并据此构建有力的无罪、罪轻、责任切割或证明力削弱逻辑。你的受众是资深律师，你的回答必须专业、克制、证据驱动、可直接进入办案工作流。

【交互红线】
1. 绝对禁止在开篇使用负面、否定或批判性的词汇，例如“严重脱节”“致命风险”“逻辑硬伤”等。
2. 即使发现用户当前思路与现有证据存在偏差，也必须先从材料中提炼对用户有利的一面并予以专业肯定。
3. 对潜在薄弱点的提示，只能放在第三部分，并以“建设性建议”的方式提出补强方案，不得用压制性、否定性表达破坏答复基调。

【强制输出结构：三段论】
你在回答用户时，原则上必须采用以下三部分结构，并使用清晰标题与重点标记：

第一部分：开篇直接回应与定调（顺势而为）
- 直接回答用户最关心的核心问题，不绕行，不铺垫空话。
- 优先提炼材料中最有利于用户辩护方向的事实特征，并给予专业、肯定的评价。
- 开篇语气必须稳健、正向、建设性，形成可继续展开辩护的主线。

第二部分：深度事实与逻辑论证（核心输出）
- 将繁杂事实、附件内容、资金数据、交易节点结构化映射到法律评价要素上。
- 处理资金流水或财务数据时，原则上围绕以下四个维度展开，并尽可能引用精确时间、金额、对手方、动作作为支撑：
  1. 资金来源特征：谁出资，谁实际承担成本或风险。
  2. 关键节点资金动作：谁过桥，谁保全，谁主导关键支付或回补。
  3. 资金回流与闭环情况：是否存在闭环结算、同额呼应、原路回流、秒进秒出。
  4. 最终权益归属：谁最终受益，谁控制处分，谁承担盈亏。
- 若不是资金类问题，也应将案件事实映射到核心法律构成要件、举证责任、归责路径和抗辩空间上。
- 必须用清晰层级、加粗小标题、分段论证，使主审律师可以快速提取可用论点。

第三部分：进一步完善思路与下一步行动引导（策略升华与互动）
- 总结当前证据对诉讼、辩护、质证或谈判策略的价值，说明其如何在法庭或书状中被使用。
- 委婉指出当前证据链仍需补强之处，并提出具体、可执行的补强建议，例如补充何种账户材料、沟通记录、合同条款、审批链或第三方证据。
- 对风险提示必须保持建设性表达，例如“为了让这条防线更加稳固，建议进一步补充……”。
- 必须以一句开放式服务性问句结尾，主动询问下一步需要继续完成的工作，例如图表化、质证提纲、证据目录、检索清单、书状段落等。

【专项要求：资金流水与数据材料】
当用户上传银行流水、财务报表、交易记录或 Excel/PDF 附件时，你必须兼具辩护律师与数据分析专家双重视角：
- 优先识别与用户辩护方向相契合的资金特征，再展开论证。
- 必须关注资金来源、关键转付、闭环回流、实际收益人、异常时间间隔、等额划转、高频主体交易等特征。
- 论证时尽可能写出可核验的数据节点，例如“某年某月某日某时收到某金额，随后多久转出至何账户，因此支持何种法律评价”。

【不可逾越的底线】
1. 反幻觉：绝不捏造法条、案号、裁判观点或证据内容。遇到盲区，必须明确写明“目前未检索到明确依据”或“现有材料尚不足以确认”。
2. 证据优先：如果用户上传了附件，必须以附件原文和附件数据为第一分析顺位，不得脱离附件事实空泛发挥。
3. 溯源要求：引用外部资料、法规、司法解释、裁判文书或监管文件时，应尽量提供发文机关、年份和可核验信息；若启用联网检索，必须附原文超链接。
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
请针对这些拆解出的关键词进行深度搜索，交叉比对后，输出最终的定制化法律分析意见。
强制要求：
1) 结论必须可追溯到中国大陆现行有效法律法规、司法解释、指导性案例或公报案例；
2) 每个关键外部依据必须在句末添加 Markdown 超链接；
3) 必须围绕案件事实展开推演，识别并肯定有利事实/有利论点，同时提示诉讼风险与其他注意事项；
4) 若附件事实不足或证据链存在断裂，必须明确写出举证风险；
5) 不得编造法条、案号或裁判观点。
`;

const FORENSIC_FINANCE_KEYWORDS = [
  "资金往来",
  "账户流水",
  "流水",
  "闭环",
  "代持",
  "辩护意见",
  "符合辩护",
  "转入",
  "转出",
  "证券",
  "质押",
  "解押",
  "证转银",
  "资金分析",
];

const FORENSIC_FINANCE_SPECIAL_PROMPT = `
【专项分析模式：资金穿透审查】
该模式下，你必须与主系统指令保持一致，严格使用“三段论”结构，并优先服务辩护论证。

第一部分必须先直接回应并定调：
- 先概括当前流水中最有利于用户辩护方向的核心特征，例如代持匹配、资金闭环、垫资特征、收益归属分离、行为受托属性等。
- 开篇不得使用负面或否定式语言。

第二部分必须展开深度事实论证：
- 先绘制全局资金地图，明确资金来源方、过桥方、证券机构、最终沉淀方、潜在实际受益人。
- 必须围绕四个维度展开：
  1. 资金来源特征：谁出资、谁承担成本、谁承担风险。
  2. 关键节点资金动作：谁在解押、保全、补仓、回补节点发挥决定性作用。
  3. 资金回流与闭环情况：是否存在同额呼应、原路回流、秒进秒出、闭环结算。
  4. 最终权益归属：谁实际控制处分，谁最终取得收益，谁只是通道或名义账户。
- 至少列出 8 条“时间-金额-对手方-动作-法律意义”节点。
- 必须主动识别异常特征：秒进秒出、等额划转、特定主体高频交易、短时过桥、闭环回流。

第三部分必须做策略升华：
- 说明这些资金特征如何服务于无罪、罪轻、主观明知不足、非法占有目的不足、责任从属性或证明标准不足等辩护方向。
- 以建设性方式提示证据链中仍需补强之处，并给出具体补强建议。
- 结尾必须追加一句开放式问句，引导用户选择下一步工作，例如生成资金闭环图、证据目录、质证提纲或书状段落。
`;

const CHEN_QIUMING_STYLE_HINT = `
【同题高质量对齐要求】
针对“陈秋明-辩护意见-资金往来”类问题，输出风格需贴近以下方法：
1) 先给“核心结论一句话”，再进入分节论证；
2) 至少 8 条交易节点，节点中必须含“时间、金额、对手方、动作、法律意义”；
3) 对每个结论都要写清“为什么该流水支持/削弱该辩护观点”；
4) 结尾必须给“可直接用于庭审的证据组织建议”（按证据编号/证明目的/质证风险）。
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
const uploadedAttachments = new Map();
const attachmentMaterializationTasks = new Map();
const processingFiles = new Map();
const docMindJobRegistry = new Map();
const attachmentJobs = new Map();
const attachmentJobByIdempotency = new Map();
const attachmentJobQueue = [];
let attachmentJobRunning = 0;
const conversationProgress = new Map();
const UPLOAD_TMP_DIR = path.join(__dirname, ".upload-tmp");
fs.mkdirSync(UPLOAD_TMP_DIR, { recursive: true });
const wordExtractor = new WordExtractor();
const uploadStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_TMP_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(String(file.originalname || "")).slice(0, 12);
    const unique = `${Date.now()}_${crypto.randomBytes(8).toString("hex")}${ext}`;
    cb(null, unique);
  },
});
const uploadMulter = multer({
  storage: uploadStorage,
  limits: {
    files: 1,
    fileSize: MAX_BINARY_ATTACHMENT_BYTES,
  },
});
const chatRateLimiter = createInMemoryRateLimiter({
  windowMs: RATE_LIMIT_WINDOW_MS,
  maxRequests: RATE_LIMIT_MAX_REQUESTS,
});

function getConversationProgressKey(userId, conversationId) {
  return `${userId}::${conversationId}`;
}

function setConversationProgress(userId, conversationId, stage, message) {
  const key = getConversationProgressKey(userId, conversationId);
  conversationProgress.set(key, {
    stage: String(stage || "processing"),
    message: String(message || "处理中"),
    updatedAt: Date.now(),
  });
}

function clearConversationProgress(userId, conversationId) {
  const key = getConversationProgressKey(userId, conversationId);
  conversationProgress.delete(key);
}

app.disable("x-powered-by");
app.set("trust proxy", TRUST_PROXY);

const RENDER_EXTERNAL_URL = String(process.env.RENDER_EXTERNAL_URL || "").trim();
const EFFECTIVE_CORS_ORIGINS = (() => {
  const origins = [...ALLOWED_CORS_ORIGINS];
  if (RENDER_EXTERNAL_URL && !origins.includes(RENDER_EXTERNAL_URL)) {
    origins.push(RENDER_EXTERNAL_URL);
  }
  if (origins.length === 0) {
    origins.push("*");
  }
  return origins;
})();
if (EFFECTIVE_CORS_ORIGINS.length > 0) {
  console.log("[CORS允许来源]:", EFFECTIVE_CORS_ORIGINS.join(", "));
}

const corsOptions = {
  origin(origin, callback) {
    callback(null, isCorsOriginAllowed(origin, EFFECTIVE_CORS_ORIGINS));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"],
  optionsSuccessStatus: 204,
  maxAge: 86_400,
};
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));
app.use(express.json({ limit: `${JSON_BODY_LIMIT_MB}mb` }));
app.use(express.static(path.join(__dirname)));

function inferMimeTypeFromFilename(filename) {
  const lower = String(filename || "").toLowerCase();
  if (lower.endsWith(".txt")) return "text/plain";
  if (lower.endsWith(".md")) return "text/markdown";
  if (lower.endsWith(".csv")) return "text/csv";
  if (lower.endsWith(".json")) return "application/json";
  if (lower.endsWith(".pdf")) return "application/pdf";
  if (lower.endsWith(".png")) return "image/png";
  if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
  if (lower.endsWith(".webp")) return "image/webp";
  if (lower.endsWith(".doc")) return "application/msword";
  if (lower.endsWith(".docx")) return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
  if (lower.endsWith(".xls")) return "application/vnd.ms-excel";
  if (lower.endsWith(".xlsx")) return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
  return "";
}

function normalizeUploadMimeType(rawMimeType, filename) {
  const raw = String(rawMimeType || "").trim().toLowerCase();
  if (raw && raw !== "application/octet-stream") return raw;
  return inferMimeTypeFromFilename(filename);
}

function isTextLikeMimeType(mimeType) {
  if (!mimeType) return false;
  if (TEXT_MIME_TYPES.has(mimeType)) return true;
  return mimeType.startsWith("text/");
}

function nextUploadAttachmentId() {
  return `att_${Date.now()}_${crypto.randomBytes(8).toString("hex")}`;
}

async function safeUnlink(filePath) {
  if (!filePath) return;
  try {
    await fsp.unlink(filePath);
  } catch {
    // ignore
  }
}

async function readUtf8TextLimited(filePath, maxChars) {
  let output = "";
  const stream = fs.createReadStream(filePath, { encoding: "utf8" });
  try {
    for await (const chunk of stream) {
      output += chunk;
      if (output.length >= maxChars) {
        stream.destroy();
        break;
      }
    }
  } finally {
    stream.destroy();
  }
  return output.slice(0, maxChars);
}

async function downloadRemoteFileToTemp({ fileUrl, expectedSize, fileName }) {
  const safeName = sanitizeObjectName(fileName || "file");
  const ext = path.extname(safeName).slice(0, 16);
  const maxRetries = 3;
  let lastError = null;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    const tempPath = path.join(
      UPLOAD_TMP_DIR,
      `remote_${Date.now()}_${crypto.randomBytes(8).toString("hex")}${ext}`
    );
    const perAttemptTimeout = OSS_FETCH_TIMEOUT_MS + (attempt - 1) * 30_000;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), perAttemptTimeout);

    let output;
    try {
      console.log(
        `[远程文件下载] attempt=${attempt}/${maxRetries}`,
        `url_prefix=${String(fileUrl || "").slice(0, 100)}...`,
        `timeout=${perAttemptTimeout}ms`
      );
      const response = await fetch(fileUrl, {
        method: "GET",
        signal: controller.signal,
      });
      if (!response.ok || !response.body) {
        throw new Error(`远程文件拉取失败：HTTP ${response.status}`);
      }

      output = fs.createWriteStream(tempPath);
      const reader = response.body.getReader();
      let total = 0;
      const maxBytes = Math.max(MAX_BINARY_ATTACHMENT_BYTES, Number(expectedSize) || 0);

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;
        total += value.byteLength;
        if (total > maxBytes) {
          throw new Error(`远程附件超过限制（>${Math.floor(maxBytes / 1024 / 1024)}MB）`);
        }
        if (!output.write(Buffer.from(value))) {
          await once(output, "drain");
        }
      }
      output.end();
      await once(output, "finish");
      console.log(`[远程文件下载成功] size=${total} attempt=${attempt}`);
      return {
        path: tempPath,
        size: total,
      };
    } catch (error) {
      lastError = error;
      if (output && !output.destroyed) {
        output.destroy();
      }
      await safeUnlink(tempPath);
      const detail = normalizeErrorMessage(error);
      const isRetryable = /abort|timeout|ECONNRESET|ECONNREFUSED|ETIMEDOUT|network|socket|EAI_AGAIN/i.test(detail);
      console.warn(
        `[远程文件下载失败] attempt=${attempt}/${maxRetries}`,
        `retryable=${isRetryable}`,
        `error=${detail}`
      );
      if (!isRetryable || attempt >= maxRetries) {
        throw error;
      }
      await sleep(2000 * attempt);
    } finally {
      clearTimeout(timeout);
    }
  }
  throw lastError || new Error("远程文件下载失败");
}

async function parseWordToText(filePath, mimeType) {
  if (mimeType === "application/vnd.openxmlformats-officedocument.wordprocessingml.document") {
    const result = await mammoth.extractRawText({ path: filePath });
    return String(result?.value || "");
  }
  if (mimeType === "application/msword") {
    const extracted = await wordExtractor.extract(filePath);
    return String(extracted?.getBody?.() || "");
  }
  return "";
}

function parseExcelToText(filePath) {
  const workbook = XLSX.readFile(filePath, {
    cellText: true,
    cellDates: true,
  });
  const sheets = [];
  for (const sheetName of workbook.SheetNames || []) {
    const worksheet = workbook.Sheets[sheetName];
    if (!worksheet) continue;
    const csv = XLSX.utils.sheet_to_csv(worksheet, { blankrows: false }).trim();
    if (!csv) continue;
    sheets.push(`【工作表：${sheetName}】\n${csv}`);
  }
  return sheets.join("\n\n");
}

async function parsePdfToText(filePath) {
  const buffer = await fsp.readFile(filePath);
  const parsed = await pdfParse(buffer);
  const text = String(parsed?.text || "")
    .replace(/\u0000/g, "")
    .replace(/\r\n/g, "\n")
    .trim();
  return text;
}

function createTaggedError(code, message, detail = "", statusCode = 500) {
  const error = new Error(message);
  error.code = code;
  error.detail = detail;
  error.statusCode = statusCode;
  return error;
}

let docMindClientInstance = null;
let ossClientInstance = null;
let stsClientInstance = null;

function hasOssStsConfig() {
  return Boolean(
    OSS_STS_ENABLED &&
      OSS_STS_ROLE_ARN &&
      OSS_ACCESS_KEY_ID &&
      OSS_ACCESS_KEY_SECRET &&
      OSS_BUCKET &&
      OSS_REGION
  );
}

function sanitizeStsSessionName(value) {
  const raw = String(value || "")
    .replace(/[^a-zA-Z0-9@._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  return raw || "session";
}

function buildStsPolicyForObject(objectKey) {
  const normalizedObjectKey = String(objectKey || "").replace(/^\/+/, "");
  const bucketResource = `acs:oss:*:*:${OSS_BUCKET}`;
  const objectResource = `acs:oss:*:*:${OSS_BUCKET}/${normalizedObjectKey}`;
  return JSON.stringify({
    Version: "1",
    Statement: [
      {
        Effect: "Allow",
        Action: [
          "oss:PutObject",
          "oss:InitiateMultipartUpload",
          "oss:UploadPart",
          "oss:CompleteMultipartUpload",
          "oss:AbortMultipartUpload",
          "oss:ListParts",
        ],
        Resource: [bucketResource, objectResource],
      },
    ],
  });
}

function getAliyunStsClient() {
  if (stsClientInstance) return stsClientInstance;
  if (!OSS_ACCESS_KEY_ID || !OSS_ACCESS_KEY_SECRET) {
    throw createTaggedError("OSS_STS_NOT_CONFIGURED", "OSS STS 未配置完整，请检查环境变量。", "", 500);
  }
  const config = new OpenApi.Config({
    accessKeyId: OSS_ACCESS_KEY_ID,
    accessKeySecret: OSS_ACCESS_KEY_SECRET,
    endpoint: OSS_STS_ENDPOINT,
    regionId: OSS_STS_REGION_ID,
  });
  stsClientInstance = new AlibabaCloudSts.default(config);
  return stsClientInstance;
}

async function issueOssStsCredentials({ userId, objectKey }) {
  if (!hasOssStsConfig()) {
    throw createTaggedError("OSS_STS_NOT_CONFIGURED", "OSS STS 未配置完整，请检查角色与环境变量。", "", 500);
  }
  const client = getAliyunStsClient();
  const sessionName = sanitizeStsSessionName(
    `${OSS_STS_SESSION_PREFIX}-${String(userId || "user").slice(0, 20)}-${Date.now()}`
  );
  const request = new AlibabaCloudSts.AssumeRoleRequest({
    roleArn: OSS_STS_ROLE_ARN,
    roleSessionName: sessionName,
    durationSeconds: Math.max(900, Math.min(3600, OSS_STS_DURATION_SECONDS)),
    policy: buildStsPolicyForObject(objectKey),
    externalId: OSS_STS_EXTERNAL_ID || undefined,
  });
  const runtime = new TeaUtil.RuntimeOptions({
    connectTimeout: 15000,
    readTimeout: 30000,
    autoretry: true,
    maxAttempts: 2,
  });
  const response = await client.assumeRoleWithOptions(request, runtime);
  const credentials = response?.body?.credentials;
  if (!credentials?.accessKeyId || !credentials?.accessKeySecret || !credentials?.securityToken) {
    throw createTaggedError("OSS_STS_ISSUE_FAILED", "STS 临时凭证签发失败：返回字段不完整。", "", 502);
  }
  return {
    accessKeyId: String(credentials.accessKeyId),
    accessKeySecret: String(credentials.accessKeySecret),
    securityToken: String(credentials.securityToken),
    expiration: String(credentials.expiration || ""),
  };
}

function getOssClient() {
  if (ossClientInstance) return ossClientInstance;
  if (!OSS_BUCKET || !OSS_ACCESS_KEY_ID || !OSS_ACCESS_KEY_SECRET || !OSS_REGION) {
    throw createTaggedError("OSS_NOT_CONFIGURED", "OSS 签名链接生成失败，请检查 OSS 配置。", "", 500);
  }
  const endpointHost = normalizeHost(OSS_ENDPOINT);
  const explicitEndpoint = endpointHost
    ? `${OSS_FORCE_HTTPS ? "https" : "http"}://${endpointHost}`
    : undefined;
  ossClientInstance = new OSS({
    region: OSS_REGION,
    bucket: OSS_BUCKET,
    accessKeyId: OSS_ACCESS_KEY_ID,
    accessKeySecret: OSS_ACCESS_KEY_SECRET,
    secure: OSS_FORCE_HTTPS,
    endpoint: explicitEndpoint,
    authorizationV4: false,
  });
  console.log(
    "[OSS客户端初始化]",
    `region=${OSS_REGION}`,
    `bucket=${OSS_BUCKET}`,
    `endpoint=${explicitEndpoint || "(auto)"}`,
    `secure=${OSS_FORCE_HTTPS}`
  );
  return ossClientInstance;
}

function buildSignedOssReadUrl(objectKey, expires = OSS_SIGNED_URL_EXPIRE_SECONDS) {
  const client = getOssClient();
  return client.signatureUrl(String(objectKey || "").replace(/^\/+/, ""), {
    expires: Math.max(60, expires),
    method: "GET",
  });
}

function getAliyunDocMindClient() {
  if (docMindClientInstance) return docMindClientInstance;
  if (!OSS_ACCESS_KEY_ID || !OSS_ACCESS_KEY_SECRET) {
    throw createTaggedError("DOCMIND_NOT_CONFIGURED", "扫描件文字识别失败，请确认服务端 OCR 配置完整。", "", 500);
  }
  const config = new OpenApi.Config({
    accessKeyId: OSS_ACCESS_KEY_ID,
    accessKeySecret: OSS_ACCESS_KEY_SECRET,
    endpoint: DOCMIND_ENDPOINT,
    regionId: DOCMIND_REGION_ID,
  });
  docMindClientInstance = new AlibabaCloudDocMind.default(config);
  return docMindClientInstance;
}

function createAliyunOcrResponseError(responseCode, detail) {
  const numericStatus = Number(responseCode);
  const statusCode = Number.isFinite(numericStatus) && numericStatus >= 400 && numericStatus < 600
    ? numericStatus
    : 502;
  return createTaggedError(
    "SCANNED_PDF_OCR_FAILED",
    "扫描件文字识别失败，请确认图片清晰度或稍后再试。",
    String(detail || responseCode || "OCR failed"),
    statusCode
  );
}

async function probeSignedUrlForOcr(fileUrl) {
  const url = String(fileUrl || "").trim();
  if (!url) {
    throw createTaggedError(
      "SCANNED_PDF_OCR_FAILED",
      "读取云端案卷失败，请重试或截取关键页上传",
      "missing signed file url",
      400
    );
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Math.min(30_000, DOCMIND_HTTP_TIMEOUT_MS));
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: { Range: "bytes=0-1023" },
      signal: controller.signal,
    });
    const ok = response.status === 200 || response.status === 206;
    if (!ok) {
      const text = await response.text().catch(() => "");
      console.error("[阿里云真实拦截原因]:", String(text || "").slice(0, 4_000));
      throw createTaggedError(
        "SCANNED_PDF_OCR_FAILED",
        "读取云端案卷失败，请重试或截取关键页上传",
        `signed-url-http-${response.status}`,
        502
      );
    }
    if (response.body && typeof response.body.cancel === "function") {
      response.body.cancel().catch(() => {});
    }
  } catch (error) {
    if (String(error?.code || "") === "SCANNED_PDF_OCR_FAILED") throw error;
    const detail = normalizeErrorMessage(error);
    if (/unexpected token\s*['"]?</i.test(detail) || detail.includes("<?xml")) {
      console.error("[阿里云真实拦截原因]:", detail);
    }
    throw createTaggedError(
      "SCANNED_PDF_OCR_FAILED",
      "读取云端案卷失败，请重试或截取关键页上传",
      detail,
      502
    );
  } finally {
    clearTimeout(timeout);
  }
}

async function runDocMindWithRetry(label, task) {
  let lastError = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      return await task();
    } catch (error) {
      lastError = error;
      const statusCode = Number(error?.statusCode || 0);
      const detail = normalizeErrorMessage(error).toLowerCase();
      const deterministicClientError =
        (statusCode >= 400 && statusCode < 500) ||
        detail.includes("illegalimageurl") ||
        detail.includes("invalid url");
      const retryable = !deterministicClientError && isTransientError(error);
      if (!retryable || attempt >= 3) {
        throw error;
      }
      const waitMs = 1_500 * attempt;
      console.warn(`[审计] DocMind重试: ${label} attempt=${attempt}/3 wait=${waitMs}ms error=${normalizeErrorMessage(error)}`);
      await delay(waitMs);
    }
  }
  throw lastError || new Error(`DocMind ${label} failed`);
}

function extractTextFromDocMindData(data) {
  const preferred = [];
  const fallback = [];
  const seen = new Set();

  const pushLine = (line, target) => {
    const normalized = String(line || "").replace(/\u0000/g, "").trim();
    if (!normalized) return;
    if (normalized.length < 2) return;
    if (seen.has(normalized)) return;
    seen.add(normalized);
    target.push(normalized);
  };

  const walk = (value, pathKeys = []) => {
    if (value == null) return;
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (!trimmed) return;
      if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
        try {
          walk(JSON.parse(trimmed), pathKeys);
          return;
        } catch {
          // keep raw text
        }
      }
      const keyHint = String(pathKeys[pathKeys.length - 1] || "").toLowerCase();
      const isPreferred = /(markdown|md|text|content|paragraph|line|table|cell|result|output|value|body)/i.test(keyHint);
      for (const line of trimmed.split(/\r?\n/)) {
        pushLine(line, isPreferred ? preferred : fallback);
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item) => walk(item, pathKeys));
      return;
    }
    if (typeof value === "object") {
      Object.entries(value).forEach(([key, val]) => walk(val, [...pathKeys, key]));
    }
  };

  walk(data, []);
  const output = preferred.length > 0 ? preferred : fallback;
  return output.join("\n").trim();
}

function extractDocMindFailureReason(body) {
  const reasons = [];
  const push = (value) => {
    const text = String(value || "").trim();
    if (!text) return;
    if (!reasons.includes(text)) reasons.push(text);
  };

  push(body?.message);
  const data = body?.data;
  if (data && typeof data === "object") {
    for (const key of ["reason", "failReason", "error", "errorMessage", "message", "detail", "details"]) {
      push(data[key]);
    }
  }

  if (reasons.length > 0) {
    return reasons.join(" | ");
  }
  try {
    return JSON.stringify(body || {});
  } catch {
    return String(body || "");
  }
}

function logDocMindRawError(label, error) {
  const raw = error && typeof error === "object" ? error : { value: error };
  const props = {};
  if (raw && typeof raw === "object") {
    for (const key of Object.getOwnPropertyNames(raw)) {
      props[key] = raw[key];
    }
  }
  console.error(`${label} message:`, String(error?.message || error || ""));
  console.error(`${label} stack:`, String(error?.stack || ""));
  console.error(`${label} props:`, props);
  if (error?.cause) {
    console.error(`${label} cause:`, error.cause);
  }
}

async function submitDocMindStructureJob({ signedUrl, fileName }) {
  const client = getAliyunDocMindClient();
  const safeFileName = normalizeFilename(fileName || "document.pdf", "document.pdf");
  const extension = path.extname(safeFileName).replace(/^\./, "").toLowerCase() || "pdf";
  const request = new AlibabaCloudDocMind.SubmitDocStructureJobRequest({
    fileName: safeFileName,
    fileNameExtension: extension,
    fileUrl: signedUrl,
  });
  const response = await withTimeout(
    runDocMindWithRetry("submit-doc-structure-job", () => client.submitDocStructureJob(request)),
    DOCMIND_HTTP_TIMEOUT_MS
  );
  const code = String(response?.body?.code || "").trim();
  if (code && code !== "200") {
    throw createAliyunOcrResponseError(code, String(response?.body?.message || code));
  }
  const jobId = String(response?.body?.data?.id || "").trim();
  if (!jobId) {
    throw createTaggedError(
      "SCANNED_PDF_OCR_FAILED",
      "读取云端案卷失败，请重试或截取关键页上传",
      "DocMind submit missing job id",
      502
    );
  }
  return jobId;
}

function getDocMindRegistryEntry(objectKey) {
  const normalizedObjectKey = String(objectKey || "").trim().replace(/^\/+/, "");
  if (!normalizedObjectKey) return { key: "", entry: null };
  return {
    key: normalizedObjectKey,
    entry: docMindJobRegistry.get(normalizedObjectKey) || null,
  };
}

function upsertDocMindRegistry(objectKey, patch) {
  const normalizedObjectKey = String(objectKey || "").trim().replace(/^\/+/, "");
  if (!normalizedObjectKey) return null;
  const prev = docMindJobRegistry.get(normalizedObjectKey) || {};
  const next = {
    ...prev,
    ...patch,
    updatedAt: Date.now(),
  };
  docMindJobRegistry.set(normalizedObjectKey, next);
  return next;
}

async function getOrCreateDocMindJobId({
  objectKey,
  existingJobId = "",
  signedUrl,
  fileName,
}) {
  const normalizedObjectKey = String(objectKey || "").trim().replace(/^\/+/, "");
  const normalizedExistingJobId = String(existingJobId || "").trim();
  if (!normalizedObjectKey) {
    return normalizedExistingJobId || submitDocMindStructureJob({ signedUrl, fileName });
  }

  if (normalizedExistingJobId) {
    upsertDocMindRegistry(normalizedObjectKey, {
      jobId: normalizedExistingJobId,
      state: "processing",
    });
    return normalizedExistingJobId;
  }

  const current = docMindJobRegistry.get(normalizedObjectKey);
  const cachedJobId = String(current?.jobId || "").trim();
  if (cachedJobId) {
    upsertDocMindRegistry(normalizedObjectKey, {
      state: String(current?.state || "processing") === "ready" ? "ready" : "processing",
    });
    return cachedJobId;
  }

  if (current?.submitPromise && typeof current.submitPromise.then === "function") {
    return current.submitPromise;
  }

  const submitPromise = (async () => {
    const jobId = await submitDocMindStructureJob({ signedUrl, fileName });
    upsertDocMindRegistry(normalizedObjectKey, {
      jobId,
      state: "processing",
      submitCount: Number(current?.submitCount || 0) + 1,
      submitPromise: null,
    });
    return jobId;
  })()
    .catch((error) => {
      upsertDocMindRegistry(normalizedObjectKey, {
        state: "failed",
        lastError: normalizeErrorMessage(error),
        submitPromise: null,
      });
      throw error;
    });

  upsertDocMindRegistry(normalizedObjectKey, {
    state: "submitting",
    submitPromise,
  });

  return submitPromise;
}

async function pollDocMindStructureResult(jobId, progressReporter = null) {
  const client = getAliyunDocMindClient();
  const maxAttempts = Math.max(1, DOCMIND_POLL_MAX_ATTEMPTS);
  const timeoutLimitMs = Math.max(DOCMIND_POLL_INTERVAL_MS, DOCMIND_POLL_TIMEOUT_MS);
  const deadlineAt = Date.now() + timeoutLimitMs;
  const RuntimeOptions = TeaUtil.RuntimeOptions;
  const runtime = new RuntimeOptions({
    connectTimeout: 15000,
    readTimeout: 30000,
    autoretry: true,
    maxAttempts: 3,
  });
  let attempt = 0;
  while (attempt < maxAttempts && Date.now() < deadlineAt) {
    attempt += 1;
    const request = new AlibabaCloudDocMind.GetDocStructureResultRequest({
      id: jobId,
      revealMarkdown: true,
      useUrlResponseBody: false,
    });
    let response = null;
    try {
      response = await withTimeout(
        runDocMindWithRetry("get-doc-structure-result", () => client.getDocStructureResultWithOptions(request, runtime)),
        DOCMIND_HTTP_TIMEOUT_MS
      );
    } catch (error) {
      const raw = normalizeErrorMessage(error).toLowerCase();
      const code = String(error?.code || "").toLowerCase();
      const networkFlaky = isNetworkError(error) || code === "econnreset" || raw.includes("aborted");
      if (networkFlaky) {
        console.warn(`[DocMind轮询网络抖动] attempt=${attempt}/${maxAttempts} code=${String(error?.code || "")} message=${String(error?.message || "")}`);
        await sleep(DOCMIND_POLL_INTERVAL_MS);
        continue;
      }
      throw error;
    }
    const body = response?.body || {};
    const responseCode = String(body?.code || "").trim();
    const statusRaw = String(body?.status || "").trim();
    const status = statusRaw.toLowerCase();
    const messageRaw = String(body?.message || "").trim();
    const isCompleted = status === "completed";
    const isFailed = status === "failed";
    const isProcessingState = status === "init" || status === "processing";
    const isProcessingMessage = /document processing/i.test(messageRaw);
    const shouldKeepWaiting = isProcessingState || isProcessingMessage;

    if (isCompleted) {
      const text = extractTextFromDocMindData(body?.data || {});
      if (!text) {
        throw createTaggedError(
          "SCANNED_PDF_OCR_FAILED",
          "读取云端案卷失败，请重试或截取关键页上传",
          "DocMind empty result",
          502
        );
      }
      return text;
    }

    if (isFailed) {
      const failReason = extractDocMindFailureReason(body);
      console.error("[DocMind失败原因]:", failReason);
      console.error("[DocMind失败响应体]:", body);
      throw createTaggedError(
        "SCANNED_PDF_OCR_FAILED",
        "读取云端案卷失败，请重试或截取关键页上传",
        String(failReason || statusRaw || "DocMind job failed"),
        502
      );
    }

    if (shouldKeepWaiting) {
      if (typeof progressReporter === "function") {
        progressReporter("ocr", `正在识别扫描件文字（任务处理中，第${attempt}/${maxAttempts}次轮询）`);
      }
      await sleep(DOCMIND_POLL_INTERVAL_MS);
      continue;
    }

    if (responseCode && responseCode !== "200") {
      throw createAliyunOcrResponseError(responseCode, String(messageRaw || responseCode));
    }

    if (typeof progressReporter === "function") {
      progressReporter("ocr", `正在识别扫描件文字（任务处理中，第${attempt}/${maxAttempts}次轮询）`);
    }
    await sleep(DOCMIND_POLL_INTERVAL_MS);
  }

  const timeoutError = createTaggedError(
    "DOCMIND_POLL_TIMEOUT",
    "扫描件识别耗时较长，系统仍在后台继续处理，请稍后再试。",
    `DocMind轮询超时（>${timeoutLimitMs}ms）`,
    504
  );
  timeoutError.jobId = String(jobId || "").trim();
  throw timeoutError;
}

async function extractTextWithFallback(
  filePath,
  fileUrl = "",
  progressReporter = null,
  sourceObjectKey = "",
  existingDocMindJobId = "",
  options = {}
) {
  const normalizedMimeType = normalizeUploadMimeType(options?.mimeType, options?.fileName || "");
  const normalizedObjectKey = String(sourceObjectKey || "").trim().replace(/^\/+/, "");
  const inferredNameFromOptions = normalizeFilename(options?.fileName || "", "document");
  const isPdf = normalizedMimeType === "application/pdf"
    || /\.pdf$/i.test(inferredNameFromOptions)
    || /\.pdf$/i.test(normalizedObjectKey);
  const preferRemoteOnly = Boolean(options?.preferRemoteOnly);
  const normalizedFilePath = typeof filePath === "string" ? filePath.trim() : "";

  let pdfParsedText = "";
  let fileSizeBytes = 0;
  if (isPdf && normalizedFilePath && !preferRemoteOnly) {
    try {
      const stat = await fsp.stat(normalizedFilePath);
      fileSizeBytes = Number(stat?.size || 0);
    } catch (error) {
      console.warn("[审计] 文件大小读取失败，继续尝试本地解析：", normalizeErrorMessage(error));
    }

    const shouldSkipLocalPdfParse = fileSizeBytes > LARGE_PDF_PARSE_THRESHOLD_BYTES;
    if (shouldSkipLocalPdfParse) {
      console.warn(
        `[审计] PDF体积过大，跳过本地pdf-parse: size=${fileSizeBytes} threshold=${LARGE_PDF_PARSE_THRESHOLD_BYTES}`
      );
    } else {
      try {
        pdfParsedText = await parsePdfToText(normalizedFilePath);
      } catch (error) {
        console.warn("[审计] pdf-parse 提取失败，将尝试 OCR 兜底：", normalizeErrorMessage(error));
      }
    }
  } else if (isPdf && preferRemoteOnly) {
    console.log("[审计] 命中URL-only模式，跳过本地pdf-parse");
  } else if (isPdf && !normalizedFilePath) {
    console.log("[审计] 无本地文件路径，直接进入云端OCR/DocMind模式");
  }

  if (isPdf && pdfParsedText.length === 0) {
    console.warn("[审计] pdf-parse 提取字符数为 0，疑似扫描件 PDF");
  }

  if (isPdf && pdfParsedText.length >= OCR_PDF_MIN_TEXT_CHARS) {
    return {
      rawText: pdfParsedText,
      extractor: "pdf-parse",
    };
  }

  let signedFileUrl = String(fileUrl || "").trim();
  if (normalizedObjectKey) {
    try {
      signedFileUrl = buildSignedOssReadUrl(normalizedObjectKey, OSS_SIGNED_URL_EXPIRE_SECONDS);
    } catch (error) {
      throw createTaggedError(
        "SCANNED_PDF_OCR_FAILED",
        "读取云端案卷失败，请重试或截取关键页上传",
        normalizeErrorMessage(error),
        502
      );
    }
  }

  if (!signedFileUrl) {
    throw createTaggedError(
      "SCANNED_PDF_OCR_FAILED",
      "读取云端案卷失败，请重试或截取关键页上传",
      "missing OCR file URL",
      502
    );
  }

  console.log("[审计] 触发阿里云 OCR 兜底识别");
  if (typeof progressReporter === "function") {
    progressReporter("ocr", "正在识别扫描件文字");
  }

  try {
    await probeSignedUrlForOcr(signedFileUrl);
    const inferredName = normalizedObjectKey
      ? path.basename(normalizedObjectKey)
      : inferredNameFromOptions
      || path.basename(normalizedFilePath || (isPdf ? "document.pdf" : "document.docx"));
    const cachedBefore = normalizedObjectKey ? getDocMindRegistryEntry(normalizedObjectKey).entry : null;
    const normalizedJobId = await getOrCreateDocMindJobId({
      objectKey: normalizedObjectKey,
      existingJobId: existingDocMindJobId,
      signedUrl: signedFileUrl,
      fileName: inferredName,
    });
    const fromRegistry = Boolean(
      cachedBefore
      && !String(existingDocMindJobId || "").trim()
      && String(cachedBefore.jobId || "").trim() === normalizedJobId
    );
    if (String(existingDocMindJobId || "").trim()) {
      console.log(`[审计] DocMind任务续轮询: jobId=${normalizedJobId}`);
    } else if (fromRegistry) {
      console.log(`[审计] DocMind任务复用: jobId=${normalizedJobId}`);
    } else {
      console.log(`[审计] DocMind任务提交成功: jobId=${normalizedJobId}`);
    }
    const ocrText = await pollDocMindStructureResult(normalizedJobId, progressReporter);
    if (normalizedObjectKey) {
      upsertDocMindRegistry(normalizedObjectKey, {
        jobId: normalizedJobId,
        state: "ready",
        lastError: "",
      });
    }
    return {
      rawText: ocrText,
      extractor: "aliyun-docmind-async",
      docMindJobId: normalizedJobId,
    };
  } catch (error) {
    if (String(error?.code || "") === "DOCMIND_POLL_TIMEOUT") {
      if (normalizedObjectKey) {
        upsertDocMindRegistry(normalizedObjectKey, {
          jobId: String(error?.jobId || existingDocMindJobId || "").trim(),
          state: "processing",
          lastError: "",
        });
      }
      throw error;
    }
    logDocMindRawError("[DocMind完整错误]", error);
    const detail = normalizeErrorMessage(error);
    if (normalizedObjectKey) {
      upsertDocMindRegistry(normalizedObjectKey, {
        state: "failed",
        lastError: detail,
      });
    }
    if (/unexpected token\s*['"]?</i.test(detail) || detail.includes("<?xml")) {
      console.error("[阿里云真实拦截原因]:", detail);
    }
    throw createTaggedError(
      "SCANNED_PDF_OCR_FAILED",
      "读取云端案卷失败，请重试或截取关键页上传",
      detail,
      502
    );
  }
}

function looksLikeFinancialPdf(name, text) {
  const nameText = String(name || "").toLowerCase();
  const preview = String(text || "").slice(0, 20_000).toLowerCase();
  const keywords = [
    "流水",
    "银行",
    "账户",
    "交易",
    "对账单",
    "明细",
    "借方",
    "贷方",
    "余额",
    "证转银",
    "finance",
    "statement",
    "transaction",
    "account",
    "debit",
    "credit",
    "balance",
  ];
  return keywords.some((keyword) => nameText.includes(keyword) || preview.includes(keyword));
}

function cleanFinancialPdfText(rawText) {
  const lines = String(rawText || "")
    .replace(/\u00a0/g, " ")
    .split(/\r?\n/)
    .map((line) => line.replace(/\s+/g, " ").trim())
    .filter(Boolean);

  const dateLineRegex = /(?:\b\d{4}[-/.年]?\d{2}[-/.月]?\d{2}(?:日)?\b|\b20[1-2]\d{5}\b)/;
  const skipLineRegex = /^(?:第\s*\d+\s*页|page\s*\d+|打印日期|打印时间|交易流水明细|账户交易明细|账户明细表|银行声明|仅供参考|客户回单|电子回单|币种|开户行|开户地址|卡号|账号：|户名：|本页小计|本页合计)$/i;

  const kept = [];
  for (const line of lines) {
    if (skipLineRegex.test(line)) continue;
    if (!dateLineRegex.test(line)) continue;
    kept.push(line);
  }

  return {
    text: kept.join("\n"),
    lineCount: kept.length,
    originalLineCount: lines.length,
  };
}

function normalizeFinancialCell(value) {
  return String(value || "")
    .replace(/[|｜]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractDateFromFinancialLine(line) {
  const match = String(line || "").match(/(?:\b\d{4}[-/.年]?\d{2}[-/.月]?\d{2}(?:日)?\b|\b20[1-2]\d{5}\b)/);
  return match ? normalizeFinancialCell(match[0]) : "";
}

function extractAmountsFromFinancialLine(line) {
  return [...String(line || "").matchAll(/[+-]?\d{1,3}(?:,\d{3})*(?:\.\d{2})|[+-]?\d+\.\d{2}/g)]
    .map((match) => String(match[0] || "").trim())
    .filter((value) => /\d/.test(value));
}

function normalizeAmountToken(value) {
  return String(value || "").replace(/,/g, "").trim();
}

function extractLabeledAmount(line, labels) {
  const labelPattern = labels.map((item) => item.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
  const match = String(line || "").match(
    new RegExp(`(?:${labelPattern})[:：\\s]*([+-]?\\d{1,3}(?:,\\d{3})*(?:\\.\\d{2})|[+-]?\\d+\\.\\d{2})`, "i")
  );
  return match?.[1] ? normalizeAmountToken(match[1]) : "";
}

function splitFinancialAmounts(line) {
  const raw = String(line || "");
  const normalizedAmounts = extractAmountsFromFinancialLine(raw).map(normalizeAmountToken);
  let income = extractLabeledAmount(raw, ["贷方", "收入", "入账", "转入", "收入金额", "贷记"]);
  let expense = extractLabeledAmount(raw, ["借方", "支出", "出账", "转出", "支出金额", "借记"]);
  let balance = extractLabeledAmount(raw, ["余额", "可用余额", "账户余额", "本次余额"]);

  const lower = raw.toLowerCase();
  const isIncomeLine = /贷方|收入|入账|转入|收款|入金|credited|deposit/.test(raw);
  const isExpenseLine = /借方|支出|出账|转出|付款|付出|debit|payment/.test(raw);

  if (!income && !expense && normalizedAmounts.length >= 3) {
    income = isExpenseLine ? "" : normalizedAmounts[0];
    expense = isExpenseLine ? normalizedAmounts[0] : normalizedAmounts[1];
    balance = balance || normalizedAmounts[2];
  } else if (!income && !expense && normalizedAmounts.length === 2) {
    if (isIncomeLine && !isExpenseLine) {
      income = normalizedAmounts[0];
      balance = balance || normalizedAmounts[1];
    } else if (isExpenseLine && !isIncomeLine) {
      expense = normalizedAmounts[0];
      balance = balance || normalizedAmounts[1];
    } else {
      income = normalizedAmounts[0];
      balance = balance || normalizedAmounts[1];
    }
  } else if (!income && !expense && normalizedAmounts.length === 1) {
    const amount = normalizedAmounts[0];
    if (/^-/.test(amount) || isExpenseLine) expense = amount.replace(/^-/, "");
    else income = amount.replace(/^\+/, "");
  }

  if (!balance && normalizedAmounts.length > 0) {
    balance = normalizedAmounts[normalizedAmounts.length - 1];
  }

  if (income && balance === income && normalizedAmounts.length === 1) {
    balance = "";
  }
  if (expense && balance === expense && normalizedAmounts.length === 1) {
    balance = "";
  }

  return {
    income: income || "",
    expense: expense || "",
    balance: balance || "",
  };
}

function extractCounterpartyFromFinancialLine(line) {
  const raw = String(line || "");
  const labeledPatterns = [
    /(?:对方户名|对手方|交易对手|付款方|收款方|对方名称|户名|摘要说明)[:：]?\s*([^\s,，;；]{2,32})/,
    /(?:付款人|收款人|对方账号名称)[:：]?\s*([^\s,，;；]{2,32})/,
  ];
  for (const pattern of labeledPatterns) {
    const match = raw.match(pattern);
    if (match?.[1]) return normalizeFinancialCell(match[1]);
  }

  const stripped = raw
    .replace(/(?:\b\d{4}[-/.年]?\d{2}[-/.月]?\d{2}(?:日)?\b|\b20[1-2]\d{5}\b)/g, " ")
    .replace(/[+-]?\d{1,3}(?:,\d{3})*(?:\.\d{2})|[+-]?\d+\.\d{2}/g, " ")
    .replace(/(?:余额|借方|贷方|收入|支出|转入|转出|摘要|备注|币种|人民币|本币|账号|卡号|交易地点|渠道|柜台|网银|手机银行)/g, " ");
  const tokens = stripped
    .split(/\s+/)
    .map((token) => token.trim())
    .filter(Boolean)
    .filter((token) => /[\u4e00-\u9fa5a-zA-Z]/.test(token))
    .filter((token) => !/^(摘要|备注|交易|银行|账户|账号|卡号)$/.test(token))
    .sort((a, b) => b.length - a.length);
  return tokens[0] ? normalizeFinancialCell(tokens[0]).slice(0, 32) : "";
}

function extractSummaryFromFinancialLine(line, date, amount, counterparty) {
  const raw = String(line || "");
  const explicitMatch = raw.match(/(?:摘要|备注|附言|用途|说明)[:：]?\s*(.+)$/);
  if (explicitMatch?.[1]) {
    return normalizeFinancialCell(explicitMatch[1]).slice(0, 80);
  }

  let summary = raw;
  if (date) summary = summary.replace(date, " ");
  if (counterparty) summary = summary.replace(counterparty, " ");
  if (amount) summary = summary.replace(amount, " ");
  summary = summary
    .replace(/[|｜]/g, " ")
    .replace(/(?:余额|借方|贷方|收入|支出|转入|转出|摘要|备注|附言|用途|说明|币种|人民币|本币|账号|卡号|对方户名|对手方)/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return summary.slice(0, 80);
}

function buildStructuredFinancialRows(cleanedText) {
  const lines = String(cleanedText || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const rows = [];
  for (const rawLine of lines) {
    const date = extractDateFromFinancialLine(rawLine);
    if (!date) continue;
    const amountColumns = splitFinancialAmounts(rawLine);
    const counterparty = extractCounterpartyFromFinancialLine(rawLine);
    const summary = extractSummaryFromFinancialLine(
      rawLine,
      date,
      amountColumns.income || amountColumns.expense || amountColumns.balance,
      counterparty
    );
    rows.push({
      date,
      income: amountColumns.income,
      expense: amountColumns.expense,
      balance: amountColumns.balance,
      counterparty,
      summary,
      raw: normalizeFinancialCell(rawLine).slice(0, 220),
    });
  }
  return rows;
}

function buildFinancialChunkSummaries(rows) {
  const chunkSize = Math.max(40, FINANCIAL_SUMMARY_CHUNK_SIZE);
  const chunks = [];
  for (let i = 0; i < rows.length; i += chunkSize) {
    const chunkRows = rows.slice(i, i + chunkSize);
    if (chunkRows.length === 0) continue;

    const counterparties = new Map();
    for (const row of chunkRows) {
      const key = String(row.counterparty || "未识别对手方").trim();
      counterparties.set(key, (counterparties.get(key) || 0) + 1);
    }
    const topCounterparties = [...counterparties.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, count]) => `${name}(${count})`)
      .join("、");

    const representative = chunkRows
      .slice(0, 3)
      .map((row) =>
        `${row.date} | 收入:${row.income || "-"} | 支出:${row.expense || "-"} | 余额:${row.balance || "-"} | ${row.counterparty || "对手方待识别"} | ${row.summary || row.raw}`
      )
      .join("\n");

    chunks.push(
      [
        `分段 ${chunks.length + 1}`,
        `时间范围：${chunkRows[0].date} 至 ${chunkRows[chunkRows.length - 1].date}`,
        `交易条数：${chunkRows.length}`,
        `高频对手方：${topCounterparties || "未识别"}`,
        `代表性节点：`,
        representative,
      ].join("\n")
    );
  }
  return chunks;
}

function buildFinancialDataPayload({ rawText, attachmentName }) {
  const cleaned = cleanFinancialPdfText(rawText);
  let cleanedText = String(cleaned.text || "").trim();
  let truncated = false;

  console.log(`[审计] 原始提取字符数: ${String(rawText || "").length}`);
  console.log(`[审计] 正则清洗后字符数: ${cleanedText.length}`);
  if (String(rawText || "").length === 0) {
    console.warn("[审计] 原始提取字符数为 0，疑似扫描件 PDF");
  }

  if (cleanedText.length > FINANCIAL_DATA_MAX_CHARS) {
    cleanedText = cleanedText.slice(0, FINANCIAL_DATA_MAX_CHARS);
    truncated = true;
  }

  if (!cleanedText) {
    let fallbackText = String(rawText || "").replace(/\s+\n/g, "\n").trim();
    if (fallbackText.length > FINANCIAL_DATA_MAX_CHARS) {
      fallbackText = fallbackText.slice(0, FINANCIAL_DATA_MAX_CHARS);
      truncated = true;
    }
    cleanedText = fallbackText;
  }

  if (!cleanedText) {
    return {
      text: "",
      truncated,
      lineCount: cleaned.lineCount,
      originalLineCount: cleaned.originalLineCount,
      structuredRowCount: 0,
      usedChunkSummary: false,
    };
  }

  const rows = buildStructuredFinancialRows(cleanedText);
  const structuredLines = rows.map((row) =>
    `${row.date || "日期待识别"} | ${row.income || "-"} | ${row.expense || "-"} | ${row.balance || "-"} | ${row.counterparty || "对手方待识别"} | ${row.summary || "摘要待识别"}`
  );
  let usedChunkSummary = false;
  let structuredBlock = structuredLines.join("\n");
  let chunkSummaryText = "";

  if (structuredBlock.length > FINANCIAL_SUMMARY_TRIGGER_CHARS) {
    usedChunkSummary = true;
    chunkSummaryText = buildFinancialChunkSummaries(rows).join("\n\n");
    structuredBlock = structuredLines.slice(0, Math.max(20, FINANCIAL_DETAIL_KEEP_ROWS)).join("\n");
  }

  const noteParts = [
    `来源附件：${attachmentName || "PDF附件"}`,
    `保留交易行数：${cleaned.lineCount}`,
    `原始行数：${cleaned.originalLineCount}`,
    `结构化条数：${rows.length}`,
    usedChunkSummary ? `分段摘要：已启用（每 ${FINANCIAL_SUMMARY_CHUNK_SIZE} 条一段）` : "分段摘要：未启用",
    truncated ? `状态：已按 ${FINANCIAL_DATA_MAX_CHARS} 字符安全截断` : "状态：未截断",
  ];

  const payloadSections = [
    `<financial_data>`,
    noteParts.join(" | "),
    "",
  ];

  if (chunkSummaryText) {
    payloadSections.push("<chunk_summaries>");
    payloadSections.push(chunkSummaryText);
    payloadSections.push("</chunk_summaries>");
    payloadSections.push("");
  }

  if (structuredBlock) {
    payloadSections.push("<structured_transactions>");
    payloadSections.push("日期 | 收入 | 支出 | 余额 | 对手方 | 摘要");
    payloadSections.push(structuredBlock);
    payloadSections.push("</structured_transactions>");
    payloadSections.push("");
  }

  if (!chunkSummaryText) {
    payloadSections.push("<raw_transaction_lines>");
    payloadSections.push(cleanedText);
    payloadSections.push("</raw_transaction_lines>");
    payloadSections.push("");
  }

  payloadSections.push("</financial_data>");

  let finalText = payloadSections.join("\n").trim();
  if (finalText.length > FINANCIAL_DATA_MAX_CHARS) {
    finalText = finalText.slice(0, FINANCIAL_DATA_MAX_CHARS);
    truncated = true;
  }

  return {
    text: finalText,
    truncated,
    lineCount: cleaned.lineCount,
    originalLineCount: cleaned.originalLineCount,
    structuredRowCount: rows.length,
    usedChunkSummary,
  };
}

function createDeferredUploadedAttachmentRecord({
  userId,
  conversationId,
  objectKey,
  fileName,
  mimeType,
  size,
}) {
  return {
    id: nextUploadAttachmentId(),
    userId,
    conversationId,
    name: normalizeFilename(fileName, "附件"),
    mimeType,
    size: Number(size) || 0,
    createdAt: Date.now(),
    expiresAt: Date.now() + UPLOAD_ATTACHMENT_TTL_MS,
    kind: "remote",
    objectKey: String(objectKey || "").replace(/^\/+/, ""),
    fileUri: "",
    data: "",
    geminiFileName: "",
    text: "",
    textLimit: TEXT_EXTRACT_MAX_CHARS,
    isFinancialData: false,
    usedChunkSummary: false,
    parseStatus: "pending",
    parseMessage: "AI后台识别排队中",
    parseError: "",
    parseAttempts: 0,
    docMindJobId: "",
    etag: "",
    jobId: "",
    idempotencyKey: "",
    traceId: "",
    parseStartedAt: 0,
    parseFinishedAt: 0,
    contextInjected: false,
  };
}

async function uploadBinaryFileToGemini({ filePath, mimeType, displayName }) {
  const uploadedFile = await ai.files.upload({
    file: filePath,
    config: {
      mimeType,
      displayName,
    },
  });
  const fileUri = String(uploadedFile?.uri || "").trim();
  const geminiFileName = String(uploadedFile?.name || "").trim();
  if (!fileUri || !geminiFileName) {
    throw new Error("文件上传到 Gemini 失败：未返回有效文件 URI");
  }
  return { fileUri, geminiFileName };
}

async function createUploadedAttachmentRecord({
  file,
  userId,
  conversationId,
  sourceFileUrl = "",
  sourceObjectKey = "",
  sourceDocMindJobId = "",
  progressReporter = null,
}) {
  const name = normalizeFilename(file?.originalname, "附件");
  const mimeType = normalizeUploadMimeType(file?.mimetype, name);
  if (!mimeType) {
    throw new Error(`不支持的附件类型：${name}`);
  }
  const filePath = typeof file?.path === "string" ? file.path : "";
  const fileSize = Number(file?.size) || 0;
  const normalizedSourceFileUrl = String(sourceFileUrl || "").trim();
  const useUrlOnlyDocPipeline = Boolean(normalizedSourceFileUrl)
    && fileSize > URL_ONLY_DOC_PARSE_THRESHOLD_BYTES
    && (mimeType === "application/pdf" || WORD_MIME_TYPES.has(mimeType));

  const record = {
    id: nextUploadAttachmentId(),
    userId,
    conversationId,
    name,
    mimeType,
    size: fileSize,
    createdAt: Date.now(),
    expiresAt: Date.now() + UPLOAD_ATTACHMENT_TTL_MS,
    kind: "text",
    text: "",
    textLimit: TEXT_EXTRACT_MAX_CHARS,
    isFinancialData: false,
    usedChunkSummary: false,
    fileUri: "",
    data: "",
    geminiFileName: "",
    docMindJobId: "",
  };

  try {
    if (isTextLikeMimeType(mimeType)) {
      if (!filePath) {
        throw new Error(`附件缺少本地文件路径：${name}`);
      }
      const text = await readUtf8TextLimited(filePath, TEXT_EXTRACT_MAX_CHARS);
      record.kind = "text";
      record.text = text.slice(0, TEXT_EXTRACT_MAX_CHARS);
      record.textLimit = TEXT_EXTRACT_MAX_CHARS;
      return record;
    }

    if (WORD_MIME_TYPES.has(mimeType)) {
      if (useUrlOnlyDocPipeline) {
        const extractedWord = await extractTextWithFallback(
          "",
          normalizedSourceFileUrl,
          progressReporter,
          sourceObjectKey,
          sourceDocMindJobId,
          { mimeType, fileName: name, preferRemoteOnly: true }
        );
        const text = String(extractedWord?.rawText || "");
        record.kind = "text";
        record.mimeType = "text/plain";
        record.text = text.slice(0, TEXT_EXTRACT_MAX_CHARS);
        record.textLimit = TEXT_EXTRACT_MAX_CHARS;
        record.docMindJobId = String(extractedWord?.docMindJobId || "");
        return record;
      }
      if (!filePath) {
        throw new Error(`附件缺少本地文件路径：${name}`);
      }
      const text = await parseWordToText(filePath, mimeType);
      record.kind = "text";
      record.mimeType = "text/plain";
      record.text = String(text || "").slice(0, TEXT_EXTRACT_MAX_CHARS);
      record.textLimit = TEXT_EXTRACT_MAX_CHARS;
      return record;
    }

    if (EXCEL_MIME_TYPES.has(mimeType)) {
      if (!filePath) {
        throw new Error(`附件缺少本地文件路径：${name}`);
      }
      const text = parseExcelToText(filePath);
      record.kind = "text";
      record.mimeType = "text/plain";
      record.text = String(text || "").slice(0, TEXT_EXTRACT_MAX_CHARS);
      record.textLimit = TEXT_EXTRACT_MAX_CHARS;
      return record;
    }

    if (mimeType === "application/pdf") {
      const shouldPreferTextPath = fileSize >= LARGE_PDF_PARSE_THRESHOLD_BYTES;
      const preferRemoteOnly = useUrlOnlyDocPipeline || (!filePath && Boolean(normalizedSourceFileUrl));
      try {
        const extractedPdf = await extractTextWithFallback(
          filePath,
          normalizedSourceFileUrl,
          progressReporter,
          sourceObjectKey,
          sourceDocMindJobId,
          { mimeType, fileName: name, preferRemoteOnly }
        );
        const pdfText = extractedPdf.rawText;
        if (pdfText) {
          if (looksLikeFinancialPdf(name, pdfText)) {
            const financialPayload = buildFinancialDataPayload({
              rawText: pdfText,
              attachmentName: name,
            });
            if (financialPayload.text) {
              record.kind = "text";
              record.mimeType = "text/plain";
              record.text = financialPayload.text;
              record.textLimit = FINANCIAL_DATA_MAX_CHARS;
              record.isFinancialData = true;
              record.usedChunkSummary = Boolean(financialPayload.usedChunkSummary);
              record.docMindJobId = String(extractedPdf?.docMindJobId || "");
              return record;
            }
          }

          if (shouldPreferTextPath) {
            record.kind = "text";
            record.mimeType = "text/plain";
            record.text = pdfText.slice(0, TEXT_EXTRACT_MAX_CHARS);
            record.textLimit = TEXT_EXTRACT_MAX_CHARS;
            record.docMindJobId = String(extractedPdf?.docMindJobId || "");
            return record;
          }

          if (preferRemoteOnly || !filePath) {
            record.kind = "text";
            record.mimeType = "text/plain";
            record.text = pdfText.slice(0, TEXT_EXTRACT_MAX_CHARS);
            record.textLimit = TEXT_EXTRACT_MAX_CHARS;
            record.docMindJobId = String(extractedPdf?.docMindJobId || "");
            return record;
          }
        }
      } catch (pdfParseError) {
        const errorCode = String(pdfParseError?.code || "");
        if (errorCode === "SCANNED_PDF_OCR_FAILED" || errorCode === "DOCMIND_POLL_TIMEOUT") {
          throw pdfParseError;
        }
        if (shouldPreferTextPath) {
          throw new Error(`PDF 解析失败，无法进入轻量清洗链路：${normalizeErrorMessage(pdfParseError)}`);
        }
      }
    }

    if (PDF_IMAGE_MIME_TYPES.has(mimeType)) {
      if (!filePath) {
        throw new Error(`附件缺少本地文件路径：${name}`);
      }
      try {
        const uploadedBinary = await uploadBinaryFileToGemini({
          filePath,
          mimeType,
          displayName: name,
        });
        record.kind = "binary";
        record.fileUri = uploadedBinary.fileUri;
        record.geminiFileName = uploadedBinary.geminiFileName;
        return record;
      } catch (uploadError) {
        // PDF上传失败时，优先走文本解析兜底，避免用户上传即失败。
        if (mimeType === "application/pdf") {
          try {
            const extractedPdf = await extractTextWithFallback(
              filePath,
              normalizedSourceFileUrl,
              progressReporter,
              sourceObjectKey,
              sourceDocMindJobId,
              { mimeType, fileName: name, preferRemoteOnly: !filePath && Boolean(normalizedSourceFileUrl) }
            );
            const pdfText = extractedPdf.rawText;
            if (pdfText) {
              record.kind = "text";
              record.mimeType = "text/plain";
              record.text = pdfText.slice(0, TEXT_EXTRACT_MAX_CHARS);
              record.textLimit = TEXT_EXTRACT_MAX_CHARS;
              record.docMindJobId = String(extractedPdf?.docMindJobId || "");
              return record;
            }
          } catch (fallbackPdfError) {
            const errorCode = String(fallbackPdfError?.code || "");
            if (errorCode === "SCANNED_PDF_OCR_FAILED" || errorCode === "DOCMIND_POLL_TIMEOUT") {
              throw fallbackPdfError;
            }
            // continue fallback
          }
        }

        // 二级兜底：改为inlineData，绕过Gemini文件上传接口。
        const rawBuffer = await fsp.readFile(filePath);
        const base64 = rawBuffer.toString("base64");
        if (base64.length <= MAX_BASE64_ATTACHMENT_CHARS) {
          record.kind = "binary";
          record.fileUri = "";
          record.geminiFileName = "";
          record.data = base64;
          return record;
        }
        throw new Error(`附件上传失败，且兜底解析未成功：${normalizeErrorMessage(uploadError)}`);
      }
    }

    throw new Error(`不支持的附件类型：${name}（${mimeType}）`);
  } finally {
    await safeUnlink(filePath);
  }
}

async function deleteGeminiFileByName(geminiFileName) {
  if (!geminiFileName) return;
  try {
    await ai.files.delete({ name: geminiFileName });
  } catch {
    // ignore
  }
}

async function removeUploadedAttachmentRecord(record, { deleteRemote = true } = {}) {
  if (!record) return false;
  uploadedAttachments.delete(record.id);
  attachmentMaterializationTasks.delete(record.id);
  if (record.jobId) {
    const job = getAttachmentJobById(record.jobId);
    if (job?.attachmentIds instanceof Set) {
      job.attachmentIds.delete(record.id);
      updateAttachmentJob(job, { attachmentIds: job.attachmentIds });
      if (job.attachmentIds.size === 0 && ["queued", "running"].includes(String(job.status || "").toLowerCase())) {
        updateAttachmentJob(job, {
          status: "canceled",
          phase: "canceled",
          progress: 100,
          etaSec: 0,
          finishedAt: nowMs(),
          errorCode: "ATTACHMENT_DELETED",
          errorMessage: "附件已删除，任务取消",
        });
      }
    }
  }
  if (deleteRemote && record.kind === "binary") {
    await deleteGeminiFileByName(record.geminiFileName);
  }
  return true;
}

async function removeUploadedAttachmentByIdForUser(userId, uploadId, { deleteRemote = true } = {}) {
  const record = uploadedAttachments.get(String(uploadId || ""));
  if (!record || record.userId !== userId) return false;
  return removeUploadedAttachmentRecord(record, { deleteRemote });
}

async function removeUploadedAttachmentsByConversation(userId, conversationId) {
  const removedIds = [];
  const tasks = [];
  for (const record of uploadedAttachments.values()) {
    if (record.userId === userId && record.conversationId === conversationId) {
      removedIds.push(record.id);
      tasks.push(removeUploadedAttachmentRecord(record, { deleteRemote: true }));
    }
  }
  await Promise.allSettled(tasks);
  return removedIds.length;
}

function normalizeAttachmentIds(rawIds) {
  let input = rawIds;
  if (typeof rawIds === "string") {
    try {
      const parsed = JSON.parse(rawIds);
      input = parsed;
    } catch {
      input = [];
    }
  }
  if (!Array.isArray(input)) return [];
  const ids = [];
  const seen = new Set();
  for (const raw of input) {
    const value = String(raw || "").trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    ids.push(value);
    if (ids.length >= MAX_ATTACHMENTS) break;
  }
  return ids;
}

function mapUploadedRecordToAttachment(record) {
  if (!record) return null;
  if (record.kind === "text") {
    const textLimit = Math.max(
      1,
      Math.min(
        FINANCIAL_DATA_MAX_CHARS,
        Number(record.textLimit) > 0 ? Number(record.textLimit) : TEXT_EXTRACT_MAX_CHARS
      )
    );
    return {
      kind: "text",
      name: record.name,
      mimeType: record.mimeType || "text/plain",
      text: String(record.text || "").slice(0, textLimit),
      textLimit,
      isFinancialData: Boolean(record.isFinancialData),
      usedChunkSummary: Boolean(record.usedChunkSummary),
    };
  }
  if (record.kind === "remote") {
    return {
      kind: "remote",
      name: record.name,
      mimeType: record.mimeType,
      size: Number(record.size) || 0,
      objectKey: record.objectKey || "",
    };
  }
  return {
    kind: "binary",
    name: record.name,
    mimeType: record.mimeType,
    fileUri: record.fileUri || "",
    data: record.data || "",
  };
}

function resolveUploadedAttachments({ userId, conversationId, attachmentIds }) {
  const resolved = [];
  const missing = [];
  for (const id of attachmentIds) {
    const record = uploadedAttachments.get(id);
    if (!record || record.userId !== userId || record.conversationId !== conversationId) {
      missing.push(id);
      continue;
    }
    record.expiresAt = Date.now() + UPLOAD_ATTACHMENT_TTL_MS;
    resolved.push(record);
  }
  return { resolved, missing };
}

function findUploadedAttachmentByObjectKey({ userId, conversationId, objectKey }) {
  const normalizedObjectKey = String(objectKey || "").trim().replace(/^\/+/, "");
  if (!normalizedObjectKey) return null;
  for (const record of uploadedAttachments.values()) {
    if (!record) continue;
    if (record.userId !== userId || record.conversationId !== conversationId) continue;
    if (String(record.objectKey || "").trim() !== normalizedObjectKey) continue;
    return record;
  }
  return null;
}

function normalizeOssEtag(rawEtag) {
  return String(rawEtag || "").trim().replace(/^"+|"+$/g, "");
}

function buildAttachmentIdempotencyKey({ objectKey, size, etag }) {
  const payload = [
    String(objectKey || "").trim().replace(/^\/+/, ""),
    String(Number(size) || 0),
    normalizeOssEtag(etag),
  ].join("|");
  return crypto.createHash("sha256").update(payload).digest("hex");
}

function nextAttachmentJobId() {
  return `job_${Date.now()}_${crypto.randomBytes(8).toString("hex")}`;
}

function nextTraceId() {
  return `trace_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
}

function extractProviderRequestId(input) {
  const text = String(input || "");
  const match = text.match(/request[\s_-]?id[:=]\s*([A-Za-z0-9-]+)/i);
  return match?.[1] ? String(match[1]) : "";
}

function readHeaderValue(headers, name) {
  if (!headers || !name) return "";
  const normalized = String(name || "").toLowerCase();
  if (typeof headers.get === "function") {
    return String(headers.get(name) || headers.get(normalized) || "").trim();
  }
  if (typeof headers === "object") {
    const direct = headers[name] ?? headers[normalized];
    if (direct != null) return String(direct).trim();
  }
  return "";
}

function nowMs() {
  return Date.now();
}

function updateAttachmentJob(job, patch) {
  if (!job) return null;
  const current = attachmentJobs.get(String(job.jobId || "")) || job;
  const next = {
    ...current,
    ...patch,
    updatedAt: nowMs(),
  };
  attachmentJobs.set(next.jobId, next);
  return next;
}

function mapJobToAttachmentParseStatus(job) {
  const status = String(job?.status || "").toLowerCase();
  if (status === "succeeded") return "ready";
  if (status === "failed" || status === "canceled") return "failed";
  if (status === "running") return "processing";
  return "pending";
}

function mapJobPhaseToMessage(job) {
  const phase = String(job?.phase || "").toLowerCase();
  if (phase === "queued") return "AI后台识别排队中";
  if (phase === "splitting") return "案卷拆分处理中";
  if (phase === "uploading_to_gemini") return "正在上传案卷到 Gemini";
  if (phase === "waiting_file_active") return "正在等待 Gemini 文件激活";
  if (phase === "summarizing") return "正在生成案卷结构化摘要";
  if (phase === "answered") return "后台识别完成";
  return "AI后台深度识别中";
}

function estimateAttachmentJobEtaSeconds(job) {
  const status = String(job?.status || "").toLowerCase();
  if (["succeeded", "failed", "canceled"].includes(status)) return 0;
  const totalBytes = Math.max(1, Number(job?.size || 0));
  const estimatedMs = Math.min(
    ATTACHMENT_PARSE_MAX_ETA_MS,
    ATTACHMENT_PARSE_BASE_ETA_MS + Math.ceil(totalBytes / 1024 / 1024) * 5_000
  );
  const startedAt = Number(job?.startedAt || 0);
  if (!startedAt) return Math.ceil(estimatedMs / 1000);
  const remain = Math.max(3_000, estimatedMs - (nowMs() - startedAt));
  return Math.ceil(remain / 1000);
}

function getAttachmentJobById(jobId) {
  return attachmentJobs.get(String(jobId || "").trim()) || null;
}

function getReusableAttachmentJobByIdempotency(idempotencyKey) {
  const key = String(idempotencyKey || "").trim();
  if (!key) return null;
  const jobId = attachmentJobByIdempotency.get(key);
  if (!jobId) return null;
  const job = attachmentJobs.get(jobId);
  if (!job) {
    attachmentJobByIdempotency.delete(key);
    return null;
  }
  const status = String(job.status || "").toLowerCase();
  if (["queued", "running", "succeeded"].includes(status)) {
    return job;
  }
  return null;
}

function queueAttachmentJob(job) {
  if (!job) return;
  const status = String(job.status || "").toLowerCase();
  if (status === "queued" || status === "running" || status === "succeeded") return;
  if (attachmentJobQueue.length >= ATTACHMENT_JOB_MAX_QUEUE) {
    throw createTaggedError(
      "ATTACHMENT_QUEUE_FULL",
      "后台任务队列繁忙，请稍后重试",
      `queue=${attachmentJobQueue.length}`,
      429
    );
  }
  updateAttachmentJob(job, {
    status: "queued",
    phase: "queued",
    progress: Math.max(1, Number(job.progress || 0)),
    etaSec: estimateAttachmentJobEtaSeconds(job),
    errorCode: "",
    errorMessage: "",
  });
  attachmentJobQueue.push(job.jobId);
  drainAttachmentJobQueue();
}

function createAttachmentJobForRecord(record, idempotencyKey) {
  const job = {
    jobId: nextAttachmentJobId(),
    traceId: nextTraceId(),
    idempotencyKey,
    userId: record.userId,
    conversationId: record.conversationId,
    objectKey: record.objectKey,
    size: Number(record.size) || 0,
    mimeType: record.mimeType,
    fileName: record.name,
    etag: normalizeOssEtag(record.etag),
    status: "new",
    phase: "queued",
    progress: 0,
    etaSec: estimateAttachmentJobEtaSeconds(record),
    retries: 0,
    errorCode: "",
    errorMessage: "",
    providerRequestId: "",
    splitRequestId: "",
    geminiUploadRequestId: "",
    geminiGenerateRequestId: "",
    attachmentIds: new Set([record.id]),
    createdAt: nowMs(),
    updatedAt: nowMs(),
    startedAt: 0,
    finishedAt: 0,
    summaryText: "",
  };
  attachmentJobs.set(job.jobId, job);
  attachmentJobByIdempotency.set(idempotencyKey, job.jobId);
  return job;
}

function attachRecordToJob(record, job) {
  if (!record || !job) return;
  if (!job.attachmentIds || !(job.attachmentIds instanceof Set)) {
    job.attachmentIds = new Set();
  }
  job.attachmentIds.add(record.id);
  record.jobId = job.jobId;
  record.idempotencyKey = job.idempotencyKey;
  record.traceId = job.traceId;
  const parseStatus = mapJobToAttachmentParseStatus(job);
  record.parseStatus = parseStatus;
  record.parseMessage = mapJobPhaseToMessage(job);
  record.parseError = String(job.errorMessage || "");
  record.parseStartedAt = Number(job.startedAt || record.parseStartedAt || 0);
  record.parseFinishedAt = Number(job.finishedAt || record.parseFinishedAt || 0);
  record.expiresAt = nowMs() + UPLOAD_ATTACHMENT_TTL_MS;
  uploadedAttachments.set(record.id, record);
}

async function requestSplitWorkerForPdf({ record, traceId }) {
  if (!SPLIT_WORKER_URL) {
    throw createTaggedError(
      "SPLIT_WORKER_NOT_CONFIGURED",
      "超大 PDF 需要拆分处理，请联系管理员配置拆分服务",
      "missing SPLIT_WORKER_URL",
      500
    );
  }
  const signedUrl = buildSignedOssReadUrl(record.objectKey, OSS_SIGNED_URL_EXPIRE_SECONDS);
  const maxAttempts = Math.max(1, SPLIT_WORKER_MAX_RETRIES + 1);
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), SPLIT_WORKER_TIMEOUT_MS);
    try {
      const headers = {
        "Content-Type": "application/json",
        "X-Trace-Id": traceId,
      };
      if (SPLIT_WORKER_TOKEN) {
        headers.Authorization = `Bearer ${SPLIT_WORKER_TOKEN}`;
      }
      const response = await fetch(SPLIT_WORKER_URL, {
        method: "POST",
        headers,
        body: JSON.stringify({
          objectKey: record.objectKey,
          fileName: record.name,
          mimeType: record.mimeType,
          size: Number(record.size) || 0,
          signedUrl,
          maxPartBytes: SPLIT_WORKER_PART_MAX_BYTES,
          etag: normalizeOssEtag(record.etag || ""),
          conversationId: String(record.conversationId || ""),
          userId: String(record.userId || ""),
        }),
        signal: controller.signal,
      });
      const rawText = await response.text();
      let data = {};
      try {
        data = rawText ? JSON.parse(rawText) : {};
      } catch {
        data = {};
      }
      if (!response.ok) {
        const detail = String(data?.message || rawText || `split-worker-http-${response.status}`).slice(0, 2000);
        const tagged = createTaggedError(
          "SPLIT_WORKER_FAILED",
          "案卷拆分失败，请稍后重试",
          detail,
          response.status >= 500 ? 502 : response.status
        );
        tagged.responseStatus = Number(response.status) || 0;
        throw tagged;
      }
      const splitRequestId = String(
        data?.requestId
        || response.headers.get("x-request-id")
        || response.headers.get("x-acs-request-id")
        || ""
      ).trim();
      const rawParts = Array.isArray(data?.parts) ? data.parts : [];
      const normalizedParts = rawParts
        .map((part, index) => ({
          objectKey: String(part?.objectKey || "").trim().replace(/^\/+/, ""),
          size: Number(part?.size) > 0 ? Number(part.size) : 0,
          fileName: normalizeFilename(part?.fileName || `${record.name}_part_${index + 1}.pdf`, `${record.name}_part_${index + 1}.pdf`),
        }))
        .filter((part) => Boolean(part.objectKey));
      if (normalizedParts.length === 0) {
        throw createTaggedError(
          "SPLIT_WORKER_EMPTY_PARTS",
          "案卷拆分失败，请稍后重试",
          "split worker returned empty parts",
          502
        );
      }
      console.log(
        "[拆分服务返回]:",
        `traceId=${traceId}`,
        `attempt=${attempt}/${maxAttempts}`,
        `requestId=${splitRequestId || "(empty)"}`,
        `parts=${normalizedParts.length}`,
        `objectKey=${record.objectKey}`
      );
      return {
        splitRequestId,
        parts: normalizedParts,
      };
    } catch (error) {
      lastError = error;
      const status = Number(error?.responseStatus || error?.statusCode || 0);
      const retryableStatus = status === 429 || status === 502 || status === 503 || status === 504;
      const retryable = attempt < maxAttempts && (isTransientError(error) || retryableStatus);
      console.warn(
        "[拆分服务调用失败]:",
        `traceId=${traceId}`,
        `attempt=${attempt}/${maxAttempts}`,
        `retryable=${retryable}`,
        `status=${status || 0}`,
        `detail=${normalizeErrorMessage(error)}`
      );
      if (!retryable) throw error;
      await sleep(1200 * attempt);
    } finally {
      clearTimeout(timeout);
    }
  }
  throw lastError || createTaggedError("SPLIT_WORKER_FAILED", "案卷拆分失败，请稍后重试", "unknown split worker error", 502);
}

async function waitGeminiFileActive(fileName, traceId) {
  if (!fileName || typeof ai?.files?.get !== "function") {
    return;
  }
  const startedAt = nowMs();
  while (nowMs() - startedAt < GEMINI_FILE_ACTIVE_TIMEOUT_MS) {
    const file = await ai.files.get({ name: fileName });
    const stateRaw = String(
      file?.state?.name
      || file?.state
      || file?.status
      || ""
    ).toUpperCase();
    if (!stateRaw || stateRaw === "ACTIVE" || stateRaw === "READY") {
      return;
    }
    if (stateRaw === "FAILED" || stateRaw === "ERROR") {
      throw createTaggedError(
        "GEMINI_FILE_PROCESS_FAILED",
        "Gemini 文件处理失败",
        `traceId=${traceId} fileName=${fileName} state=${stateRaw}`,
        502
      );
    }
    await sleep(GEMINI_FILE_ACTIVE_POLL_MS);
  }
  throw createTaggedError(
    "GEMINI_FILE_ACTIVE_TIMEOUT",
    "Gemini 文件激活超时，请稍后重试",
    `traceId=${traceId} fileName=${fileName}`,
    504
  );
}

async function summarizeGeminiFilePart({
  model,
  fileUri,
  mimeType,
  partIndex,
  totalParts,
  traceId,
}) {
  const response = await withTimeout(
    ai.models.generateContent({
      model,
      contents: [{
        role: "user",
        parts: [
          {
            text: `你是一名资深法律助理。请对当前案卷分片（${partIndex}/${totalParts}）生成结构化摘要，重点保留：事实时间轴、关键金额、关键主体、争议焦点、可用于法庭的证据线索。禁止编造。`,
          },
          {
            fileData: {
              fileUri,
              mimeType,
            },
          },
        ],
      }],
      config: {
        temperature: 0.1,
        topP: 0.8,
        topK: 40,
      },
    }),
    GEMINI_ATTACHMENT_SUMMARY_TIMEOUT_MS
  );
  const summary = String(response?.text || "").trim();
  if (!summary) {
    throw createTaggedError(
      "GEMINI_PART_SUMMARY_EMPTY",
      "案卷分片摘要为空",
      `traceId=${traceId} part=${partIndex}`,
      502
    );
  }
  const requestId = String(
    readHeaderValue(response?.response?.headers, "x-request-id")
    || readHeaderValue(response?.response?.headers, "x-acs-request-id")
    || extractProviderRequestId(response?.response?.requestId)
  ).trim();
  return {
    summary,
    requestId,
  };
}

async function mergeGeminiPartSummaries({ model, summaries, traceId }) {
  if (!Array.isArray(summaries) || summaries.length === 0) {
    return {
      text: "",
      requestId: "",
    };
  }
  if (summaries.length === 1) {
    return {
      text: String(summaries[0] || ""),
      requestId: "",
    };
  }
  const mergedInput = summaries
    .map((item, idx) => `【分片${idx + 1}摘要】\n${String(item || "")}`)
    .join("\n\n");
  const response = await withTimeout(
    ai.models.generateContent({
      model,
      contents: [{
        role: "user",
        parts: [{
          text: `请将以下多个案卷分片摘要合并成一份完整案卷摘要，要求：去重、保留金额和时间细节、保留主体关系、形成可用于后续问答的事实基础。\n\n${mergedInput}`,
        }],
      }],
      config: {
        temperature: 0.1,
        topP: 0.8,
        topK: 40,
      },
    }),
    GEMINI_ATTACHMENT_SUMMARY_TIMEOUT_MS
  );
  const text = String(response?.text || "").trim();
  if (!text) {
    throw createTaggedError(
      "GEMINI_SUMMARY_MERGE_EMPTY",
      "案卷摘要汇总失败",
      `traceId=${traceId}`,
      502
    );
  }
  const requestId = String(
    readHeaderValue(response?.response?.headers, "x-request-id")
    || readHeaderValue(response?.response?.headers, "x-acs-request-id")
    || extractProviderRequestId(response?.response?.requestId)
  ).trim();
  return {
    text,
    requestId,
  };
}

function collectJobAttachmentRecords(job) {
  const records = [];
  for (const attachmentId of job?.attachmentIds || []) {
    const record = uploadedAttachments.get(String(attachmentId || ""));
    if (!record) continue;
    records.push(record);
  }
  return records;
}

function markJobFailed(job, error) {
  const detail = normalizeErrorMessage(error);
  const errorCode = String(error?.code || "ATTACHMENT_JOB_FAILED").trim() || "ATTACHMENT_JOB_FAILED";
  const providerRequestId = extractProviderRequestId(detail);
  updateAttachmentJob(job, {
    status: "failed",
    phase: "failed",
    progress: 100,
    etaSec: 0,
    finishedAt: nowMs(),
    errorCode,
    errorMessage: detail,
    providerRequestId: providerRequestId || String(job.providerRequestId || ""),
  });
  const records = collectJobAttachmentRecords(job);
  for (const record of records) {
    record.parseStatus = "failed";
    record.parseMessage = "后台识别失败";
    record.parseError = detail;
    record.parseFinishedAt = nowMs();
    record.expiresAt = nowMs() + UPLOAD_ATTACHMENT_TTL_MS;
    uploadedAttachments.set(record.id, record);
  }
}

async function executeAttachmentJob(job) {
  const model = DEFAULT_MODEL;
  updateAttachmentJob(job, {
    status: "running",
    phase: "splitting",
    progress: 5,
    startedAt: job.startedAt || nowMs(),
    etaSec: estimateAttachmentJobEtaSeconds(job),
    errorCode: "",
    errorMessage: "",
  });

  const records = collectJobAttachmentRecords(job);
  const primaryRecord = records[0];
  if (!primaryRecord) {
    throw createTaggedError("ATTACHMENT_RECORD_MISSING", "附件记录不存在或已过期", job.jobId, 404);
  }
  const isPdf = String(primaryRecord.mimeType || "").toLowerCase() === "application/pdf";
  let parts = [{
    objectKey: primaryRecord.objectKey,
    size: Number(primaryRecord.size) || 0,
    fileName: primaryRecord.name,
  }];
  if (isPdf && Number(primaryRecord.size || 0) > GEMINI_PDF_MAX_BYTES) {
    const split = await requestSplitWorkerForPdf({
      record: primaryRecord,
      traceId: job.traceId,
    });
    updateAttachmentJob(job, {
      splitRequestId: String(split.splitRequestId || ""),
      providerRequestId: String(split.splitRequestId || job.providerRequestId || ""),
    });
    parts = split.parts;
  }

  const summaries = [];
  let partCounter = 0;
  for (const part of parts) {
    partCounter += 1;
    updateAttachmentJob(job, {
      phase: "uploading_to_gemini",
      progress: Math.min(90, 10 + Math.floor((partCounter / parts.length) * 70)),
      etaSec: estimateAttachmentJobEtaSeconds(job),
    });
    const signedUrl = buildSignedOssReadUrl(part.objectKey, OSS_SIGNED_URL_EXPIRE_SECONDS);
    const downloaded = await downloadRemoteFileToTemp({
      fileUrl: signedUrl,
      expectedSize: part.size || primaryRecord.size,
      fileName: part.fileName || primaryRecord.name,
    });
    let geminiFileName = "";
    try {
      const uploaded = await withTimeout(
        ai.files.upload({
          file: downloaded.path,
          config: {
            mimeType: primaryRecord.mimeType || "application/pdf",
            displayName: normalizeFilename(part.fileName || primaryRecord.name, "attachment.pdf"),
          },
        }),
        GEMINI_ATTACHMENT_SUMMARY_TIMEOUT_MS
      );
      const uploadRequestId = String(
        readHeaderValue(uploaded?.response?.headers, "x-request-id")
        || readHeaderValue(uploaded?.response?.headers, "x-acs-request-id")
        || extractProviderRequestId(uploaded?.response?.requestId)
      ).trim();
      if (uploadRequestId) {
        updateAttachmentJob(job, {
          geminiUploadRequestId: uploadRequestId,
          providerRequestId: uploadRequestId,
        });
      }
      const fileUri = String(uploaded?.uri || "").trim();
      geminiFileName = String(uploaded?.name || "").trim();
      if (!fileUri || !geminiFileName) {
        throw createTaggedError(
          "GEMINI_FILE_UPLOAD_EMPTY",
          "Gemini 文件上传失败",
          `traceId=${job.traceId} part=${partCounter}`,
          502
        );
      }

      updateAttachmentJob(job, {
        phase: "waiting_file_active",
      });
      await waitGeminiFileActive(geminiFileName, job.traceId);

      updateAttachmentJob(job, {
        phase: "summarizing",
      });
      const partSummary = await summarizeGeminiFilePart({
        model,
        fileUri,
        mimeType: primaryRecord.mimeType || "application/pdf",
        partIndex: partCounter,
        totalParts: parts.length,
        traceId: job.traceId,
      });
      summaries.push(partSummary.summary);
      if (partSummary.requestId) {
        updateAttachmentJob(job, {
          geminiGenerateRequestId: partSummary.requestId,
          providerRequestId: partSummary.requestId,
        });
      }
    } finally {
      await safeUnlink(downloaded.path);
      if (geminiFileName) {
        await deleteGeminiFileByName(geminiFileName);
      }
    }
  }

  const mergedSummary = await mergeGeminiPartSummaries({
    model,
    summaries,
    traceId: job.traceId,
  });
  if (mergedSummary.requestId) {
    updateAttachmentJob(job, {
      geminiGenerateRequestId: mergedSummary.requestId,
      providerRequestId: mergedSummary.requestId,
    });
  }
  const safeSummary = String(mergedSummary.text || "").slice(0, FINANCIAL_DATA_MAX_CHARS);
  updateAttachmentJob(job, {
    status: "succeeded",
    phase: "answered",
    progress: 100,
    etaSec: 0,
    finishedAt: nowMs(),
    summaryText: safeSummary,
    errorCode: "",
    errorMessage: "",
  });

  for (const record of records) {
    const materialized = {
      ...record,
      kind: "text",
      mimeType: "text/plain",
      text: safeSummary,
      textLimit: FINANCIAL_DATA_MAX_CHARS,
      isFinancialData: false,
      usedChunkSummary: false,
      parseStatus: "ready",
      parseMessage: "后台识别完成",
      parseError: "",
      parseFinishedAt: nowMs(),
      expiresAt: nowMs() + UPLOAD_ATTACHMENT_TTL_MS,
    };
    uploadedAttachments.set(materialized.id, materialized);
    appendBackgroundAttachmentContext(materialized);
  }
}

async function runAttachmentJob(jobId) {
  const job = getAttachmentJobById(jobId);
  if (!job) return;
  if (String(job.status || "").toLowerCase() === "canceled") return;
  for (let attempt = Number(job.retries || 0); attempt <= ATTACHMENT_JOB_MAX_RETRIES; attempt += 1) {
    try {
      updateAttachmentJob(job, { retries: attempt });
      await executeAttachmentJob(job);
      return;
    } catch (error) {
      const retryable = attempt < ATTACHMENT_JOB_MAX_RETRIES && isTransientError(error);
      if (!retryable) {
        markJobFailed(job, error);
        return;
      }
      const waitMs = 1500 * (attempt + 1);
      updateAttachmentJob(job, {
        phase: "queued",
        status: "running",
        errorCode: "",
        errorMessage: "",
      });
      await sleep(waitMs);
    }
  }
}

function drainAttachmentJobQueue() {
  if (attachmentJobRunning >= 1) return;
  while (attachmentJobQueue.length > 0 && attachmentJobRunning < 1) {
    const nextJobId = String(attachmentJobQueue.shift() || "");
    const job = getAttachmentJobById(nextJobId);
    if (!job) continue;
    if (String(job.status || "").toLowerCase() !== "queued") continue;
    attachmentJobRunning += 1;
    runAttachmentJob(nextJobId)
      .catch((error) => {
        markJobFailed(job, error);
      })
      .finally(() => {
        attachmentJobRunning = Math.max(0, attachmentJobRunning - 1);
        drainAttachmentJobQueue();
      });
  }
}

function ensureAttachmentJobForRecord(record) {
  const idempotencyKey = buildAttachmentIdempotencyKey({
    objectKey: record.objectKey,
    size: record.size,
    etag: record.etag || "",
  });
  let job = getReusableAttachmentJobByIdempotency(idempotencyKey);
  if (!job) {
    job = createAttachmentJobForRecord(record, idempotencyKey);
  }
  attachRecordToJob(record, job);
  const status = String(job.status || "").toLowerCase();
  if (status !== "succeeded" && status !== "running" && status !== "queued") {
    queueAttachmentJob(job);
  } else if (status === "running" || status === "queued") {
    drainAttachmentJobQueue();
  }
  return job;
}

function estimateAttachmentParseBudgetMs(record) {
  const sizeBytes = Math.max(0, Number(record?.size || 0));
  const sizeMb = Math.max(1, Math.ceil(sizeBytes / 1024 / 1024));
  const mimeType = String(record?.mimeType || "").toLowerCase();
  const parseAttempts = Math.max(0, Number(record?.parseAttempts || 0));
  const perMbMs = mimeType === "application/pdf" ? 5_500 : 2_400;
  const retryPenaltyMs = parseAttempts * DOCMIND_TIMEOUT_RETRY_DELAY_MS;
  const estimated = ATTACHMENT_PARSE_BASE_ETA_MS + sizeMb * perMbMs + retryPenaltyMs;
  return Math.max(45_000, Math.min(ATTACHMENT_PARSE_MAX_ETA_MS, estimated));
}

function computeAttachmentParseEtaSeconds(record) {
  const parseStatus = String(record?.parseStatus || "").toLowerCase();
  if (parseStatus === "ready" || parseStatus === "failed") {
    return 0;
  }
  const startedAt = Number(record?.parseStartedAt || 0);
  const now = Date.now();
  const budgetMs = estimateAttachmentParseBudgetMs(record);
  if (!startedAt || startedAt > now) {
    return Math.ceil(budgetMs / 1000);
  }
  const elapsedMs = Math.max(0, now - startedAt);
  const remainMs = Math.max(3_000, budgetMs - elapsedMs);
  return Math.ceil(remainMs / 1000);
}

function computeAttachmentProgressPercent(record) {
  const parseStatus = String(record?.parseStatus || "").toLowerCase();
  if (parseStatus === "ready") return 100;
  if (parseStatus === "failed") return 100;
  const startedAt = Number(record?.parseStartedAt || 0);
  if (!startedAt) return 6;
  const now = Date.now();
  const budgetMs = estimateAttachmentParseBudgetMs(record);
  const elapsedMs = Math.max(0, now - startedAt);
  const ratio = Math.min(0.95, elapsedMs / Math.max(1, budgetMs));
  return Math.max(8, Math.floor(ratio * 100));
}

function mapUploadedAttachmentStatus(record) {
  if (!record) return null;
  const job = record.jobId ? getAttachmentJobById(record.jobId) : null;
  const jobParseStatus = job ? mapJobToAttachmentParseStatus(job) : "";
  const jobMessage = job ? mapJobPhaseToMessage(job) : "";
  const jobEta = job ? estimateAttachmentJobEtaSeconds(job) : 0;
  const jobProgress = job ? Math.max(1, Math.min(100, Number(job.progress || 0))) : 0;
  const base = {
    id: record.id,
    name: record.name,
    conversationId: record.conversationId,
    kind: record.kind,
    mimeType: record.mimeType,
    size: Number(record.size) || 0,
    updatedAt: Math.max(
      Number(record.parseFinishedAt || 0),
      Number(record.parseStartedAt || 0),
      Number(record.createdAt || 0)
    ),
  };

  if (record.kind !== "remote") {
    return {
      ...base,
      parseStatus: "ready",
      parseMessage: "附件已可用于问答",
      parseError: "",
      etaSeconds: 0,
      progressPercent: 100,
      jobId: String(record.jobId || ""),
      providerRequestId: String(job?.providerRequestId || ""),
    };
  }

  const parseStatus = String(jobParseStatus || record.parseStatus || "pending").toLowerCase();
  const fallbackMessage = parseStatus === "ready"
    ? "后台识别完成"
    : parseStatus === "failed"
    ? "后台识别失败"
    : parseStatus === "processing"
    ? "正在识别扫描件文字"
    : "AI后台深度识别中";

  return {
    ...base,
    parseStatus,
    parseMessage: String(jobMessage || record.parseMessage || fallbackMessage),
    parseError: String(job?.errorMessage || record.parseError || ""),
    etaSeconds: Number(job ? jobEta : computeAttachmentParseEtaSeconds(record)),
    progressPercent: Number(job ? jobProgress : computeAttachmentProgressPercent(record)),
    parseStartedAt: Number(record.parseStartedAt || 0),
    parseFinishedAt: Number(record.parseFinishedAt || 0),
    jobId: String(record.jobId || ""),
    providerRequestId: String(job?.providerRequestId || ""),
  };
}

async function materializeUploadedAttachmentRecord(record, progressReporter = null) {
  if (!record || record.kind !== "remote") return record;
  if (typeof progressReporter === "function") {
    progressReporter("attachment", `正在读取附件：${record.name}`);
  }
  const signedUrl = buildSignedOssReadUrl(record.objectKey, OSS_SIGNED_URL_EXPIRE_SECONDS);
  const isLargePdfOrWord = Number(record.size || 0) > URL_ONLY_DOC_PARSE_THRESHOLD_BYTES
    && (
      String(record.mimeType || "").toLowerCase() === "application/pdf"
      || WORD_MIME_TYPES.has(String(record.mimeType || "").toLowerCase())
    );
  let processed;
  if (isLargePdfOrWord) {
    console.log(
      "[审计] 命中URL-only大文件解析，跳过本地下载:",
      `name=${record.name}`,
      `mime=${record.mimeType}`,
      `size=${Number(record.size || 0)}`
    );
    processed = await createUploadedAttachmentRecord({
      file: {
        originalname: record.name,
        mimetype: record.mimeType,
        size: Number(record.size) || 0,
      },
      userId: record.userId,
      conversationId: record.conversationId,
      sourceFileUrl: signedUrl,
      sourceObjectKey: record.objectKey,
      sourceDocMindJobId: record.docMindJobId || "",
      progressReporter,
    });
  } else {
    const downloaded = await downloadRemoteFileToTemp({
      fileUrl: signedUrl,
      expectedSize: record.size,
      fileName: record.name,
    });
    processed = await createUploadedAttachmentRecord({
      file: {
        originalname: record.name,
        mimetype: record.mimeType,
        size: downloaded.size,
        path: downloaded.path,
      },
      userId: record.userId,
      conversationId: record.conversationId,
      sourceFileUrl: signedUrl,
      sourceObjectKey: record.objectKey,
      sourceDocMindJobId: record.docMindJobId || "",
      progressReporter,
    });
  }
  const materialized = {
    ...record,
    ...processed,
    id: record.id,
    userId: record.userId,
    conversationId: record.conversationId,
    createdAt: record.createdAt,
    expiresAt: Date.now() + UPLOAD_ATTACHMENT_TTL_MS,
    objectKey: record.objectKey,
    parseAttempts: 0,
    docMindJobId: "",
  };
  uploadedAttachments.set(materialized.id, materialized);
  return materialized;
}

async function materializeUploadedAttachments(records, progressReporter = null) {
  const output = [];
  for (const record of records || []) {
    output.push(await materializeUploadedAttachmentRecord(record, progressReporter));
  }
  return output;
}

function appendBackgroundAttachmentContext(record) {
  if (!record || record.contextInjected || record.kind !== "text") return;
  const rawText = String(record.text || "").trim();
  if (!rawText) return;
  const contextText = rawText.slice(0, Math.min(ASYNC_ATTACHMENT_CONTEXT_CHARS, Number(record.textLimit) > 0 ? Number(record.textLimit) : TEXT_EXTRACT_MAX_CHARS));
  if (!contextText) return;
  const context = getConversationContext(record.userId, record.conversationId);
  appendContextMessage(context, "user", [{
    text: `【已完成后台案卷识别：${record.name}】\n以下为案卷识别内容，请在后续问答中作为既有事实基础继续分析：\n${contextText}`,
  }]);
  record.contextInjected = true;
  record.expiresAt = Date.now() + UPLOAD_ATTACHMENT_TTL_MS;
  uploadedAttachments.set(record.id, record);
}

function scheduleAttachmentMaterialization(record) {
  if (!record || record.kind !== "remote") return;
  const current = uploadedAttachments.get(record.id) || record;
  if (current.kind !== "remote") return;
  const parseStatus = String(current.parseStatus || "").toLowerCase();
  if (parseStatus === "ready") return;

  try {
    const job = ensureAttachmentJobForRecord(current);
    attachRecordToJob(current, job);
    if (String(job.status || "").toLowerCase() === "succeeded" && String(current.kind || "") === "remote") {
      const summaryText = String(job.summaryText || "").trim();
      if (summaryText) {
        const materialized = {
          ...current,
          kind: "text",
          mimeType: "text/plain",
          text: summaryText.slice(0, FINANCIAL_DATA_MAX_CHARS),
          textLimit: FINANCIAL_DATA_MAX_CHARS,
          parseStatus: "ready",
          parseMessage: "后台识别完成",
          parseError: "",
          parseFinishedAt: nowMs(),
          expiresAt: nowMs() + UPLOAD_ATTACHMENT_TTL_MS,
        };
        uploadedAttachments.set(materialized.id, materialized);
        appendBackgroundAttachmentContext(materialized);
      }
    }
  } catch (error) {
    current.parseStatus = "failed";
    current.parseMessage = "后台识别失败";
    current.parseError = normalizeErrorMessage(error);
    current.parseFinishedAt = nowMs();
    current.expiresAt = nowMs() + UPLOAD_ATTACHMENT_TTL_MS;
    uploadedAttachments.set(current.id, current);
  }
}

function uploadSingleFileMiddleware(req, res, next) {
  uploadMulter.single("file")(req, res, (error) => {
    if (!error) {
      next();
      return;
    }
    if (error instanceof multer.MulterError) {
      if (error.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({
          success: false,
          message: `附件超过上限，单个文件最大 ${Math.floor(MAX_BINARY_ATTACHMENT_BYTES / 1024 / 1024)}MB`,
        });
      }
      return res.status(400).json({
        success: false,
        message: `上传失败：${error.message}`,
      });
    }
    return next(error);
  });
}

async function handleUploadAttachment(req, res) {
  const conversationId = normalizeConversationId(req.body?.conversationId);
  if (!req.file) {
    return res.status(400).json({
      success: false,
      message: "未检测到附件文件，请重新上传",
    });
  }

  // When OSS direct upload is enabled, keep this endpoint as compatibility-only.
  // Large files must use STS multipart + /api/uploads/complete async pipeline
  // to avoid Render memory pressure.
  if (hasOssCredentials()) {
    await safeUnlink(req.file.path);
    return res.status(400).json({
      success: false,
      errorCode: "USE_OSS_ASYNC_UPLOAD",
      message: "当前环境已启用 OSS 直传，请使用 STS 分片上传通道",
    });
  }

  try {
    const record = await createUploadedAttachmentRecord({
      file: req.file,
      userId: req.authUser.id,
      conversationId,
      sourceFileUrl: "",
    });
    uploadedAttachments.set(record.id, record);

    return res.json({
      success: true,
      attachment: {
        id: record.id,
        name: record.name,
        mimeType: record.mimeType,
        size: record.size,
        kind: record.kind,
        conversationId: record.conversationId,
      },
    });
  } catch (error) {
    const detail = normalizeErrorMessage(error);
    const badRequest = /不支持的附件类型/i.test(detail);
    const ocrFailed = String(error?.code || "") === "SCANNED_PDF_OCR_FAILED";
    return res.status(ocrFailed ? 502 : badRequest ? 400 : 500).json({
      status: "error",
      success: false,
      errorCode: ocrFailed ? "SCANNED_PDF_OCR_FAILED" : "",
      message: ocrFailed
        ? "读取云端案卷失败，请重试或截取关键页上传"
        : badRequest
        ? "附件类型不受支持"
        : "附件解析或上传失败",
      error: detail,
    });
  }
}

function buildOssPostPolicy({ objectKey }) {
  const expiresAt = new Date(Date.now() + OSS_PRESIGN_EXPIRE_SECONDS * 1000).toISOString();
  const policyObject = {
    expiration: expiresAt,
    conditions: [
      ["content-length-range", 1, MAX_BINARY_ATTACHMENT_BYTES],
      { bucket: OSS_BUCKET },
      { key: objectKey },
      { success_action_status: "200" },
    ],
  };
  const policyBase64 = Buffer.from(JSON.stringify(policyObject)).toString("base64");
  const signature = signOssPolicyBase64(policyBase64);
  return {
    expiresAt,
    fields: {
      key: objectKey,
      policy: policyBase64,
      OSSAccessKeyId: OSS_ACCESS_KEY_ID,
      Signature: signature,
      success_action_status: "200",
    },
  };
}

function getPublicObjectUrl(objectKey) {
  const preferredBase = String(OSS_PUBLIC_BASE_URL || "").trim().replace(/\/+$/g, "");
  const uploadBase = getOssUploadBaseUrl().replace(/\/+$/g, "");
  const base = preferredBase || uploadBase;
  if (!base) return "";
  return `${base}/${encodeOssObjectKey(objectKey)}`;
}

async function handleUploadSts(req, res) {
  if (!hasOssCredentials()) {
    return res.status(400).json({
      success: false,
      errorCode: "OSS_NOT_CONFIGURED",
      message: "OSS 未配置，暂无法启用 STS 分片上传",
    });
  }
  if (!hasOssStsConfig()) {
    return res.status(400).json({
      success: false,
      errorCode: "OSS_STS_NOT_CONFIGURED",
      message: "OSS STS 未配置，已自动回退到普通直传链路",
    });
  }

  const conversationId = normalizeConversationId(req.body?.conversationId);
  const fileName = normalizeFilename(req.body?.fileName || req.body?.name, "附件");
  const fileSize = Number(req.body?.size) || 0;
  if (fileSize <= 0 || fileSize > MAX_BINARY_ATTACHMENT_BYTES) {
    return res.status(400).json({
      success: false,
      message: `附件大小无效，单个文件最大 ${Math.floor(MAX_BINARY_ATTACHMENT_BYTES / 1024 / 1024)}MB`,
    });
  }

  const objectKey = buildOssObjectKey({
    userId: req.authUser.id,
    conversationId,
    fileName,
  });

  try {
    const credentials = await issueOssStsCredentials({
      userId: req.authUser.id,
      objectKey,
    });
    console.log(
      "STS凭证下发:",
      `user=${req.authUser.id}`,
      `conversation=${conversationId}`,
      `size=${fileSize}`,
      `objectKey=${objectKey}`
    );
    return res.json({
      success: true,
      mode: "oss-sts-multipart",
      objectKey,
      bucket: OSS_BUCKET,
      region: OSS_REGION,
      endpoint: normalizeHost(OSS_ENDPOINT),
      secure: OSS_FORCE_HTTPS,
      partSize: Math.max(256 * 1024, OSS_MULTIPART_PART_SIZE_BYTES),
      parallel: Math.max(1, OSS_MULTIPART_PARALLEL),
      credentials,
      expiresAt: credentials.expiration,
    });
  } catch (error) {
    const detail = normalizeErrorMessage(error);
    console.error("STS签发失败:", detail);
    return res.status(502).json({
      success: false,
      errorCode: String(error?.code || "OSS_STS_ISSUE_FAILED"),
      message: "STS 临时凭证签发失败，请检查角色授权或稍后重试",
      error: detail,
    });
  }
}

async function handleUploadPresign(req, res) {
  if (!hasOssCredentials()) {
    return res.status(400).json({
      success: false,
      errorCode: "OSS_NOT_CONFIGURED",
      message: "OSS 未配置，暂无法启用直传上传",
    });
  }
  const conversationId = normalizeConversationId(req.body?.conversationId);
  const fileName = normalizeFilename(req.body?.fileName || req.body?.name, "附件");
  const mimeType = normalizeUploadMimeType(req.body?.mimeType, fileName) || "application/octet-stream";
  const fileSize = Number(req.body?.size) || 0;
  if (fileSize <= 0 || fileSize > MAX_BINARY_ATTACHMENT_BYTES) {
    return res.status(400).json({
      success: false,
      message: `附件大小无效，单个文件最大 ${Math.floor(MAX_BINARY_ATTACHMENT_BYTES / 1024 / 1024)}MB`,
    });
  }

  const objectKey = buildOssObjectKey({
    userId: req.authUser.id,
    conversationId,
    fileName,
  });
  const policy = buildOssPostPolicy({ objectKey });
  const uploadUrl = getOssUploadBaseUrl();
  const requestedMethod = String(req.body?.uploadMethod || "").trim().toUpperCase();
  const effectiveUploadMethod = ["PUT", "POST"].includes(requestedMethod)
    ? requestedMethod
    : OSS_UPLOAD_METHOD;
  try {
    if (effectiveUploadMethod === "PUT") {
      const client = getOssClient();
      const safeMime = String(mimeType || "application/octet-stream").split(";")[0].trim();
      let signedPutUrl;
      try {
        signedPutUrl = client.signatureUrl(objectKey, {
          expires: Math.max(60, OSS_PRESIGN_EXPIRE_SECONDS),
          method: "PUT",
          "Content-Type": safeMime,
        });
      } catch (signError) {
        console.error(
          "[PUT签名失败，回退POST]:",
          normalizeErrorMessage(signError)
        );
        signedPutUrl = null;
      }
      if (signedPutUrl) {
        console.log(
          "上传签名下发:",
          `user=${req.authUser.id}`,
          `conversation=${conversationId}`,
          `size=${fileSize}`,
          `objectKey=${objectKey}`,
          `mime=${safeMime}`,
          "method=PUT",
          `url_prefix=${signedPutUrl.slice(0, 120)}...`
        );
        return res.json({
          success: true,
          mode: "oss-direct",
          uploadUrl: signedPutUrl,
          method: "PUT",
          uploadHeaders: {
            "Content-Type": safeMime,
          },
          objectKey,
          objectUrl: getPublicObjectUrl(objectKey),
          expiresAt: new Date(Date.now() + OSS_PRESIGN_EXPIRE_SECONDS * 1000).toISOString(),
          maxFileSize: MAX_BINARY_ATTACHMENT_BYTES,
        });
      }
    }
  } catch (error) {
    const detail = normalizeErrorMessage(error);
    console.error("[PUT预签名异常，回退POST]:", detail);
  }

  if (!uploadUrl) {
    console.error(
      "[OSS上传地址为空]:",
      `OSS_ENDPOINT=${OSS_ENDPOINT}`,
      `OSS_BUCKET=${OSS_BUCKET}`,
      `getOssHost=${getOssHost()}`
    );
    return res.status(500).json({
      success: false,
      errorCode: "OSS_UPLOAD_URL_INVALID",
      message: "OSS 上传地址无效，请检查 OSS_ENDPOINT 配置",
    });
  }
  console.log(
    "上传签名下发:",
    `user=${req.authUser.id}`,
    `conversation=${conversationId}`,
    `size=${fileSize}`,
    `objectKey=${objectKey}`,
    `mime=${mimeType}`,
    "method=POST"
  );
  return res.json({
    success: true,
    mode: "oss-direct",
    uploadUrl,
    method: "POST",
    fields: policy.fields,
    objectKey,
    objectUrl: getPublicObjectUrl(objectKey),
    expiresAt: policy.expiresAt,
    maxFileSize: MAX_BINARY_ATTACHMENT_BYTES,
  });
}

async function handleUploadComplete(req, res) {
  if (!hasOssCredentials()) {
    return res.status(400).json({
      success: false,
      errorCode: "OSS_NOT_CONFIGURED",
      message: "OSS 未配置，暂无法完成直传回调",
    });
  }

  const conversationId = normalizeConversationId(req.body?.conversationId);
  const objectKey = String(req.body?.objectKey || "").trim().replace(/^\/+/, "");
  const fileName = normalizeFilename(req.body?.fileName || req.body?.name, path.basename(objectKey) || "附件");
  const mimeType = normalizeUploadMimeType(req.body?.mimeType, fileName);
  const expectedSize = Number(req.body?.size) || 0;
  const etag = normalizeOssEtag(req.body?.etag || req.body?.eTag || req.body?.ETag || "");

  if (!objectKey) {
    return res.status(400).json({
      success: false,
      message: "objectKey 不能为空",
    });
  }

  const ownerPrefix = `${OSS_OBJECT_PREFIX}/${sanitizeObjectName(req.authUser.id)}/${sanitizeObjectName(conversationId)}/`;
  if (!objectKey.startsWith(ownerPrefix)) {
    return res.status(403).json({
      success: false,
      message: "无权访问该对象",
    });
  }

  try {
    console.log(
      "[上传回填开始]:",
      `user=${req.authUser.id}`,
      `conversation=${conversationId}`,
      `objectKey=${objectKey}`,
      `fileName=${fileName}`,
      `mime=${mimeType}`,
      `size=${expectedSize}`,
      `etag=${etag || "(empty)"}`
    );
    const signedUrl = buildSignedOssReadUrl(objectKey, OSS_SIGNED_URL_EXPIRE_SECONDS);
    if (!signedUrl) {
      return res.status(500).json({
        success: false,
        errorCode: "OSS_SIGN_URL_FAILED",
        message: "无法生成 OSS 下载签名，请检查 OSS 配置",
      });
    }
    const existingRecord = findUploadedAttachmentByObjectKey({
      userId: req.authUser.id,
      conversationId,
      objectKey,
    });
    if (existingRecord) {
      existingRecord.expiresAt = Date.now() + UPLOAD_ATTACHMENT_TTL_MS;
      if (etag) {
        existingRecord.etag = etag;
      }
      if (existingRecord.kind === "remote") {
        scheduleAttachmentMaterialization(existingRecord);
      }
      const statusPayload = mapUploadedAttachmentStatus(existingRecord);
      const parseStatus = String(statusPayload?.parseStatus || existingRecord.parseStatus || "").toLowerCase();
      const message = parseStatus === "ready"
        ? "案卷已在后台识别完成，可直接提问。"
        : parseStatus === "failed"
        ? "案卷后台识别失败，请重新上传或截取关键页后重试。"
        : "案卷已接收，AI 正在后台深度识别中，请稍候提问...";
      const responseStatus = parseStatus === "ready"
        ? "ready"
        : parseStatus === "failed"
        ? "failed"
        : "queued";
      uploadedAttachments.set(existingRecord.id, existingRecord);
      return res.json({
        status: responseStatus,
        success: true,
        message,
        url: signedUrl,
        attachmentId: existingRecord.id,
        jobId: String(statusPayload?.jobId || existingRecord.jobId || ""),
        attachment: {
          id: existingRecord.id,
          name: existingRecord.name,
          mimeType: existingRecord.mimeType,
          size: existingRecord.size,
          kind: existingRecord.kind,
          conversationId: existingRecord.conversationId,
          source: "oss",
          parseStatus: statusPayload?.parseStatus || "",
          parseMessage: statusPayload?.parseMessage || "",
          etaSeconds: Number(statusPayload?.etaSeconds || 0),
          progressPercent: Number(statusPayload?.progressPercent || 0),
          jobId: String(statusPayload?.jobId || existingRecord.jobId || ""),
          providerRequestId: String(statusPayload?.providerRequestId || ""),
        },
      });
    }
    const record = createDeferredUploadedAttachmentRecord({
      userId: req.authUser.id,
      conversationId,
      objectKey,
      fileName,
      mimeType,
      size: expectedSize,
    });
    record.etag = etag;
    uploadedAttachments.set(record.id, record);
    scheduleAttachmentMaterialization(record);
    const statusPayload = mapUploadedAttachmentStatus(record);
    const parseStatus = String(statusPayload?.parseStatus || "").toLowerCase();
    const responseStatus = parseStatus === "ready"
      ? "ready"
      : parseStatus === "failed"
      ? "failed"
      : "queued";

    return res.json({
      status: responseStatus,
      success: true,
      message: "案卷已接收，AI 正在后台深度识别中，请稍候提问...",
      url: signedUrl,
      attachmentId: record.id,
      jobId: String(statusPayload?.jobId || record.jobId || ""),
      attachment: {
        id: record.id,
        name: record.name,
        mimeType: record.mimeType,
        size: record.size,
        kind: record.kind,
        conversationId: record.conversationId,
        source: "oss",
        parseStatus: statusPayload?.parseStatus || "",
        parseMessage: statusPayload?.parseMessage || "",
        etaSeconds: Number(statusPayload?.etaSeconds || 0),
        progressPercent: Number(statusPayload?.progressPercent || 0),
        jobId: String(statusPayload?.jobId || record.jobId || ""),
        providerRequestId: String(statusPayload?.providerRequestId || ""),
      },
    });
  } catch (error) {
    const detail = normalizeErrorMessage(error);
    const isNetwork = isNetworkError(error);
    const isTimeout = /timeout|timed out|aborted/i.test(detail);
    console.error(
      "OSS回填失败:",
      `user=${req.authUser.id}`,
      `conversation=${conversationId}`,
      `objectKey=${objectKey}`,
      detail
    );
    return res.status(isNetwork || isTimeout ? 502 : 500).json({
      status: "error",
      success: false,
      errorCode: isTimeout
        ? "OSS_FETCH_TIMEOUT"
        : isNetwork
        ? "OSS_FETCH_NETWORK_ERROR"
        : "OSS_COMPLETE_FAILED",
      message: isTimeout
        ? "直传文件回填超时，请稍后重试"
        : isNetwork
        ? "后端拉取 OSS 文件失败，请检查网络和 OSS 访问策略"
        : "直传文件回填失败",
      error: detail,
    });
  }
}

async function handleUploadStatus(req, res) {
  const conversationId = normalizeConversationId(req.body?.conversationId);
  const uploadIds = normalizeAttachmentIds(req.body?.uploadIds);
  if (uploadIds.length === 0) {
    return res.status(400).json({
      success: false,
      message: "uploadIds 不能为空",
    });
  }

  const attachments = [];
  for (const uploadId of uploadIds) {
    const record = uploadedAttachments.get(uploadId);
    if (!record || record.userId !== req.authUser.id) {
      attachments.push({
        id: uploadId,
        parseStatus: "not_found",
        parseMessage: "附件不存在或已过期",
        parseError: "",
        etaSeconds: 0,
        progressPercent: 100,
      });
      continue;
    }

    if (conversationId && record.conversationId !== conversationId) {
      attachments.push({
        id: uploadId,
        parseStatus: "not_found",
        parseMessage: "附件不属于当前会话",
        parseError: "",
        etaSeconds: 0,
        progressPercent: 100,
      });
      continue;
    }

    record.expiresAt = Date.now() + UPLOAD_ATTACHMENT_TTL_MS;
    uploadedAttachments.set(record.id, record);
    if (record.kind === "remote") {
      const parseStatus = String(record.parseStatus || "").toLowerCase();
      if (parseStatus === "pending") {
        scheduleAttachmentMaterialization(record);
      }
    }
    attachments.push(mapUploadedAttachmentStatus(record));
  }

  const processingCount = attachments.filter((item) => {
    const status = String(item?.parseStatus || "").toLowerCase();
    return status === "pending" || status === "processing";
  }).length;

  return res.json({
    success: true,
    attachments,
    processingCount,
    allReady: processingCount === 0,
    now: Date.now(),
  });
}

function serializeAttachmentJob(job) {
  if (!job) return null;
  return {
    jobId: job.jobId,
    traceId: job.traceId,
    idempotencyKey: job.idempotencyKey,
    status: String(job.status || ""),
    phase: String(job.phase || ""),
    progress: Number(job.progress || 0),
    etaSec: Number(estimateAttachmentJobEtaSeconds(job) || 0),
    retries: Number(job.retries || 0),
    errorCode: String(job.errorCode || ""),
    errorMessage: String(job.errorMessage || ""),
    providerRequestId: String(job.providerRequestId || ""),
    splitRequestId: String(job.splitRequestId || ""),
    geminiUploadRequestId: String(job.geminiUploadRequestId || ""),
    geminiGenerateRequestId: String(job.geminiGenerateRequestId || ""),
    createdAt: Number(job.createdAt || 0),
    updatedAt: Number(job.updatedAt || 0),
    startedAt: Number(job.startedAt || 0),
    finishedAt: Number(job.finishedAt || 0),
  };
}

function handleUploadJobStatus(req, res) {
  const jobId = String(req.query?.jobId || "").trim();
  if (!jobId) {
    return res.status(400).json({
      success: false,
      message: "jobId 不能为空",
    });
  }
  const job = getAttachmentJobById(jobId);
  if (!job) {
    return res.status(404).json({
      success: false,
      message: "任务不存在或已过期",
    });
  }
  if (job.userId !== req.authUser.id) {
    return res.status(403).json({
      success: false,
      message: "无权访问该任务",
    });
  }
  return res.json({
    success: true,
    job: serializeAttachmentJob(job),
  });
}

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

  const expiredRecords = [];
  for (const record of uploadedAttachments.values()) {
    if (!record || Number(record.expiresAt || 0) <= now) {
      expiredRecords.push(record);
    }
  }
  if (expiredRecords.length > 0) {
    Promise.allSettled(
      expiredRecords.map((record) =>
        removeUploadedAttachmentRecord(record, { deleteRemote: true })
      )
    ).catch(() => {});
  }

  const activeObjectKeys = new Set();
  for (const record of uploadedAttachments.values()) {
    const objectKey = String(record?.objectKey || "").trim().replace(/^\/+/, "");
    if (objectKey) activeObjectKeys.add(objectKey);
  }
  for (const [objectKey, state] of docMindJobRegistry.entries()) {
    const updatedAt = Number(state?.updatedAt || 0);
    const expired = updatedAt > 0 && updatedAt + UPLOAD_ATTACHMENT_TTL_MS <= now;
    if (!activeObjectKeys.has(objectKey) || expired) {
      docMindJobRegistry.delete(objectKey);
    }
  }

  for (const [jobId, job] of attachmentJobs.entries()) {
    const updatedAt = Number(job?.updatedAt || 0);
    const status = String(job?.status || "").toLowerCase();
    const active = status === "queued" || status === "running";
    const expired = updatedAt > 0 && updatedAt + ATTACHMENT_JOB_TTL_MS <= now;
    if (!active && expired) {
      attachmentJobs.delete(jobId);
    }
  }
  for (const [idempotencyKey, jobId] of attachmentJobByIdempotency.entries()) {
    if (!attachmentJobs.has(jobId)) {
      attachmentJobByIdempotency.delete(idempotencyKey);
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

app.get("/api/chat-progress", requireAuth, (req, res) => {
  const conversationId = normalizeConversationId(req.query?.conversationId);
  const key = getConversationProgressKey(req.authUser.id, conversationId);
  const progress = conversationProgress.get(key);
  return res.json({
    success: true,
    stage: progress?.stage || "",
    message: progress?.message || "",
    updatedAt: Number(progress?.updatedAt || 0),
  });
});

app.post("/api/uploads/sts", requireAuth, handleUploadSts);
app.post("/api/uploads/presign", requireAuth, handleUploadPresign);
app.post("/api/uploads/complete", requireAuth, handleUploadComplete);
app.post("/api/uploads/status", requireAuth, handleUploadStatus);
app.get("/api/uploads/job-status", requireAuth, handleUploadJobStatus);
app.post("/api/uploads", requireAuth, uploadSingleFileMiddleware, handleUploadAttachment);

app.post("/api/uploads/delete", requireAuth, async (req, res) => {
  const uploadId = String(req.body?.uploadId || "").trim();
  if (!uploadId) {
    return res.status(400).json({
      success: false,
      message: "uploadId 不能为空",
    });
  }
  const deleted = await removeUploadedAttachmentByIdForUser(req.authUser.id, uploadId, {
    deleteRemote: true,
  });
  return res.json({
    success: true,
    deleted,
  });
});

app.post("/api/conversations/delete", requireAuth, async (req, res) => {
  const conversationId = normalizeConversationId(req.body?.conversationId);
  const key = `${req.authUser.id}::${conversationId}`;
  const deletedContext = conversationContexts.delete(key);
  const deletedAttachments = await removeUploadedAttachmentsByConversation(req.authUser.id, conversationId);
  return res.json({
    success: true,
    deleted: deletedContext,
    deletedAttachments,
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
  if (String(error?.code || "") === "UPSTREAM_QUOTA_EXCEEDED") {
    return {
      statusCode: Number(error?.statusCode) || 429,
      errorCode: "UPSTREAM_QUOTA_EXCEEDED",
      userMessage: String(error?.message || "文件过大导致 AI 算力超限，请截取关键页后再试，或等待1分钟后重试。"),
      detail: String(error?.detail || normalizeErrorMessage(error)),
    };
  }
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
      userMessage: "文件过大导致 AI 算力超限，请截取关键页后再试，或等待1分钟后重试。",
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
    const fileUri = typeof item.fileUri === "string" ? item.fileUri.trim() : "";

    if (text) {
      normalized.push({
        kind: "text",
        name,
        mimeType: mimeType || "text/plain",
        text: text.slice(0, FINANCIAL_DATA_MAX_CHARS),
        textLimit: Math.min(
          FINANCIAL_DATA_MAX_CHARS,
          Number(item.textLimit) > 0 ? Number(item.textLimit) : MAX_TEXT_ATTACHMENT_CHARS
        ),
        isFinancialData: Boolean(item.isFinancialData) || /<financial_data>/i.test(text),
        usedChunkSummary: Boolean(item.usedChunkSummary) || /<chunk_summaries>/i.test(text),
      });
      continue;
    }

    if (fileUri && mimeType && PDF_IMAGE_MIME_TYPES.has(mimeType)) {
      normalized.push({
        kind: "binary",
        name,
        mimeType,
        fileUri,
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
      fileUri: "",
    });
  }

  return normalized;
}

function shouldUseForensicFinanceMode(userMessage, attachments) {
  const question = String(userMessage || "").toLowerCase();
  const inQuestion = FORENSIC_FINANCE_KEYWORDS.some((keyword) => question.includes(String(keyword).toLowerCase()));
  if (inQuestion) return true;

  for (const item of attachments || []) {
    if (item?.isFinancialData) return true;
    if (!item || item.kind !== "text") continue;
    const text = String(item.text || "").slice(0, 5000).toLowerCase();
    if (FORENSIC_FINANCE_KEYWORDS.some((keyword) => text.includes(String(keyword).toLowerCase()))) {
      return true;
    }
  }
  return false;
}

function shouldUseChenQiumingStyleHint(userMessage, attachments) {
  const text = String(userMessage || "").toLowerCase();
  const qHits = ["陈秋明", "辩护意见", "资金往来", "代持"].filter((k) =>
    text.includes(k.toLowerCase())
  ).length;
  if (qHits >= 2) return true;

  const attachmentText = (attachments || [])
    .filter((item) => item && item.kind === "text")
    .map((item) => String(item.text || "").toLowerCase())
    .join("\n")
    .slice(0, 20_000);
  const aHits = ["陈秋明", "陈婵君", "陈娜娜", "广州证券", "辩护意见"].filter((k) =>
    attachmentText.includes(k.toLowerCase())
  ).length;
  return aHits >= 2;
}

function buildUserParts(userMessage, attachments, extraGuidance = "") {
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
      if (attachment.isFinancialData) {
        parts.push({
          text: attachment.usedChunkSummary
            ? `以下为已清洗并分段摘要的交易流水数据，已提炼为结构化字段与分段摘要，用于降低大文件 Token 消耗并提高资金分析精度。`
            : `以下为已清洗的交易流水数据，仅保留关键交易行并结构化为日期、金额、对手方、摘要四列，用于降低大文件 Token 消耗并提高资金分析精度。`,
        });
      }
      parts.push({
        text: String(attachment.text || "").slice(
          0,
          Math.min(
            FINANCIAL_DATA_MAX_CHARS,
            Number(attachment.textLimit) > 0 ? Number(attachment.textLimit) : TEXT_EXTRACT_MAX_CHARS
          )
        ),
      });
      continue;
    }

    parts.push({ text: `${title}（${attachment.mimeType}）` });
    if (attachment.fileUri) {
      parts.push({
        fileData: {
          fileUri: attachment.fileUri,
          mimeType: attachment.mimeType,
        },
      });
    } else {
      parts.push({
        inlineData: {
          mimeType: attachment.mimeType,
          data: attachment.data,
        },
      });
    }
  }

  parts.push({
    text: "请优先依据附件内容回答。如果附件信息不足，请明确指出缺失信息。",
  });

  const guidance = String(extraGuidance || "").trim();
  if (guidance) {
    parts.push({
      text: guidance,
    });
  }

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

function shouldUsePlanAndSolvePipeline({ webSearch, timeoutMs, disablePlanAndSolve }) {
  if (disablePlanAndSolve) return false;
  return Boolean(webSearch) || Number(timeoutMs) >= COMPLEX_QUESTION_MIN_TIMEOUT_MS;
}

async function callGenerateOnce({ model, contents, webSearch, timeoutMs }) {
  try {
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
  } catch (error) {
    const raw = normalizeErrorMessage(error).toLowerCase();
    if (raw.includes("quota exceeded") || raw.includes("rate limit") || raw.includes("resource_exhausted")) {
      throw createTaggedError(
        "UPSTREAM_QUOTA_EXCEEDED",
        "文件过大导致 AI 算力超限，请截取关键页后再试，或等待1分钟后重试。",
        normalizeErrorMessage(error),
        429
      );
    }
    throw error;
  }
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

async function generateReplyWithRetry({ model, contents, webSearch, timeoutMs, userMessage, disablePlanAndSolve = false }) {
  let lastError = null;
  const maxAttempts = 3;
  const usePlanAndSolve = shouldUsePlanAndSolvePipeline({ webSearch, timeoutMs, disablePlanAndSolve });
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
  const conversationId = normalizeConversationId(req.body?.conversationId);
  const updateProgress = (stage, message) => {
    setConversationProgress(req.authUser.id, conversationId, stage, message);
  };
  const attachmentIds = normalizeAttachmentIds(req.body?.attachmentIds);
  const legacyAttachments = normalizeAttachments(req.body?.attachments);
  let attachments = legacyAttachments;
  updateProgress("thinking", "正在深度思考");
  if (attachmentIds.length > 0) {
    const uploaded = resolveUploadedAttachments({
      userId: req.authUser.id,
      conversationId,
      attachmentIds,
    });
    if (uploaded.missing.length > 0) {
      clearConversationProgress(req.authUser.id, conversationId);
      return res.status(400).json({
        success: false,
        message: "部分附件不存在、已过期，或不属于当前会话，请重新上传后再试",
        missingAttachmentIds: uploaded.missing,
      });
    }

    const remoteRecords = uploaded.resolved.filter((record) => record?.kind === "remote");
    if (remoteRecords.length > 0) {
      remoteRecords.forEach((record) => scheduleAttachmentMaterialization(record));
      const failedRecord = remoteRecords.find((record) => {
        const statusPayload = mapUploadedAttachmentStatus(record);
        return String(statusPayload?.parseStatus || record?.parseStatus || "").toLowerCase() === "failed";
      });
      if (failedRecord) {
        const failedStatus = mapUploadedAttachmentStatus(failedRecord);
        clearConversationProgress(req.authUser.id, conversationId);
        return res.status(502).json({
          status: "error",
          success: false,
          errorCode: "ATTACHMENT_PROCESSING_FAILED",
          message: "读取云端案卷失败，请重试或截取关键页上传",
          error: String(failedStatus?.parseError || failedRecord.parseError || failedRecord.parseMessage || "background parsing failed"),
        });
      }
      const activeStatus = mapUploadedAttachmentStatus(remoteRecords[0]);
      clearConversationProgress(req.authUser.id, conversationId);
      return res.json({
        status: "processing",
        success: false,
        errorCode: "ATTACHMENT_PARSING_IN_PROGRESS",
        message: "案卷过大，AI 仍在深度阅卷中，请耐心等待 1-2 分钟后再试。",
        jobId: String(activeStatus?.jobId || remoteRecords[0]?.jobId || ""),
      });
    }

    attachments = uploaded.resolved.map(mapUploadedRecordToAttachment).filter((item) => item && item.kind !== "remote");
  }
  const requestedModel = req.body?.model;
  const modelResult = resolveRequestModel(requestedModel);
  const historyMessages = normalizeConversationHistory(req.body?.history);
  const forceWebSearch = shouldForceWebSearchByQuestion(userMessage);
  const useWebSearch = Boolean(req.body?.webSearch) || forceWebSearch;
  const forensicFinanceMode = shouldUseForensicFinanceMode(userMessage, attachments);

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
  const extraGuidance = [
    forensicFinanceMode ? FORENSIC_FINANCE_SPECIAL_PROMPT : "",
    shouldUseChenQiumingStyleHint(userMessage, attachments) ? CHEN_QIUMING_STYLE_HINT : "",
  ]
    .filter(Boolean)
    .join("\n\n");
  const currentUserParts = buildUserParts(
    userMessage,
    attachments,
    extraGuidance
  );
  const contents = buildConversationContents({
    context,
    historyMessages,
    currentUserParts,
  });

  try {
    updateProgress("model", "正在深度思考");
    const generationResult = await generateReplyWithRetry({
      model: activeModel,
      contents,
      webSearch: useWebSearch,
      timeoutMs,
      userMessage,
      disablePlanAndSolve: forensicFinanceMode,
    });

    console.log(
      "收到前端提问：",
      userMessage || "（无文本问题）",
      "附件数：",
      attachments.length,
      "附件ID数：",
      attachmentIds.length,
      "资金分析模式：",
      forensicFinanceMode,
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
      status: "error",
      success: false,
      errorCode: mappedError.errorCode,
      message: mappedError.userMessage,
      error: mappedError.detail,
    });
  } finally {
    clearConversationProgress(req.authUser.id, conversationId);
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

app.listen(PORT, HOST, () => {
  console.log("✅ 汉盛智能后端服务器已成功启动！");
  console.log(`👉 监听地址：http://${HOST}:${PORT}`);
  console.log(`👉 默认模型：${DEFAULT_MODEL}`);
  console.log(`👉 可选模型：${ALLOWED_MODELS.join(", ")}`);
  console.log(`👉 上下文记忆条数：${CONTEXT_MAX_MESSAGES > 0 ? CONTEXT_MAX_MESSAGES : "不限制"}`);
  console.log(`👉 上下文保留时长：${Math.round(CONTEXT_TTL_MS / 1000 / 60)} 分钟`);
  console.log(`👉 附件上传：最多 ${MAX_ATTACHMENTS} 个/轮，单个 ${Math.floor(MAX_BINARY_ATTACHMENT_BYTES / 1024 / 1024)}MB`);
  console.log(`👉 上传架构：${hasOssCredentials() ? "OSS直传 + Gemini Files异步任务编排" : "本地直传后端（OSS未配置）"}`);
  console.log(`👉 任务队列：单实例并发=1，队列上限=${ATTACHMENT_JOB_MAX_QUEUE}`);
  console.log(`👉 Gemini PDF阈值：${Math.floor(GEMINI_PDF_MAX_BYTES / 1024 / 1024)}MB（超限触发外部拆分）`);
  console.log(`👉 外部拆分Worker：${SPLIT_WORKER_URL ? "已配置" : "未配置"}`);
  console.log(`👉 拆分调用重试：${SPLIT_WORKER_MAX_RETRIES} 次`);
  console.log(`👉 上传保留时长：${Math.round(UPLOAD_ATTACHMENT_TTL_MS / 1000 / 60)} 分钟`);
  console.log(`👉 运行环境：${NODE_ENV}`);
  console.log(`👉 接口限流：${RATE_LIMIT_MAX_REQUESTS}次/${Math.round(RATE_LIMIT_WINDOW_MS / 1000)}秒`);
});
