require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();
app.use(cors());
app.use(express.json());

// 检查是否配置了 API Key
if (!process.env.GEMINI_API_KEY) {
    console.error("⚠️ 错误: 未在 .env 文件中找到 GEMINI_API_KEY");
    process.exit(1);
}

// 初始化 Gemini 引擎 (让 SDK 自动决定最合适的 API 版本)
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// 接收前端提问的接口
app.post('/api/chat', async (req, res) => {
    try {
        const userMessage = req.body.message;
        console.log("收到前端发来的案情问题：", userMessage);

        /**
         * 关键修正：
         * 1. 尝试使用 gemini-1.5-flash-latest，这是目前最兼容的稳定版别名
         * 2. 如果依然 404，可以将下面的字符串改为 "gemini-pro"
         */
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });

        const result = await model.generateContent(userMessage);
        const responseText = result.response.text();

        // 将结果返回给前端网页
        res.json({ reply: responseText });

    } catch (error) {
        console.error("Gemini 引擎调用出错:", error);
        // 在返回给前端前，把错误详情打印得更清楚一些
        res.status(500).json({ error: "API 调用失败，建议检查 API Key 是否启用了 Gemini API 功能" });
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`✅ 汉盛智能后端服务器已成功启动！`);
    console.log(`👉 监听地址：http://localhost:3000`);
});