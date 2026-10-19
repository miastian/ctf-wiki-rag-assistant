# CTF Wiki RAG 思路助手

一个面向 CTF 学习与题目分析的本地 RAG 应用。它对固定版本的中文 CTF Wiki 进行切片和检索，使用 BGE-M3、ChromaDB、BM25 与 RRF 组织证据，再由 OpenAI 兼容模型生成带来源的多轮分析建议。

> 定位：学习与解题思路辅助，不是自动执行工具的 Agent，也不代替人工验证。

## 功能

- 覆盖 Web、Misc、Reverse、Crypto、Pwn 等 CTF 方向。
- 稠密向量与 BM25 双路检索，通过 RRF 融合排名。
- 依据题面、代码和工具输出维护多轮分析状态。
- 保留引用、适用条件和上下文轨迹；资料不足时明确说明。
- 本地 SQLite 保存会话，支持方向筛选和快捷追问。

## 仓库边界

仓库只发布源码、测试、构建配置和评测方法，不包含：

- 完整 CTF Wiki 语料及生成后的 `docs.jsonl`；
- BGE-M3 权重、Chroma 向量库和 embedding 缓存；
- 本地评测 JSON、模型回答、用量记录和会话数据；
- `.env`、API Key 及其他本机配置。

CTF Wiki 来源固定在 [`data/ctf/source-lock.json`](data/ctf/source-lock.json)，其内容许可证见 [`data/ctf/LICENSE`](data/ctf/LICENSE)。

## 本地运行

```powershell
python -m venv .venv
.venv\Scripts\pip.exe install -r requirements-ctf.txt
Copy-Item .env.example .env
```

填写 `.env` 中的 `LLM_API_KEY` 和 `LLM_MODEL`。完成语料准备、远程编码与产物导入后，构建前端并启动服务：

```powershell
Set-Location web
pnpm install
pnpm run build
Set-Location ..
.venv\Scripts\python.exe -m secrag.web --port 8766
```

访问 `http://127.0.0.1:8766/`。完整建库和导入流程见 [`docs/ctf-app.md`](docs/ctf-app.md)。

命令行问答：

```powershell
.venv\Scripts\python.exe -m secrag.cli "PNG 隐写题通常先检查什么？"
```

## 测试

```powershell
.venv\Scripts\pip.exe install -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest -q
Set-Location web
pnpm run build
```

## 文档

- [系统架构与实现](docs/project-technical-summary-20261017.md)
- [运行、远程建库与导入](docs/ctf-app.md)
- [v15 评测结论](docs/ctf-optimization-acceptance-20261017.md)
- [已知失败归因](docs/ctf-failure-attribution-20261017.md)

## 当前结果

固定快照包含 391 篇文档、3834 个片段。v15 完成 71 轮真实验收，其中 69 轮满足全部标准，2 轮存在 RSA 开根条件的证据覆盖不足。这是固定案例的验收结果，不代表通用问答准确率。
