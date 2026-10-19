# CTF Wiki 思路助手：运行与建库

## 数据边界

项目使用固定 commit 的中文 CTF Wiki。来源版本见 `data/ctf/source-lock.json`，Embedding 模型版本见 `data/ctf/model-lock.json`。

完整语料、切片、向量、索引和评测结果均为本地产物，已由 `.gitignore` 排除。GitHub 仓库只保留来源锁定文件、公开清单、处理代码和构建入口。CTF Wiki 内容许可证见 `data/ctf/LICENSE`。

## 环境

```powershell
python -m venv .venv
.venv\Scripts\pip.exe install -r requirements-ctf.txt
Copy-Item .env.example .env
```

`.env` 至少需要配置：

```dotenv
LLM_BASE_URL=https://api.openai.com/v1
LLM_API_KEY=
LLM_MODEL=
EMBED_MODEL=BAAI/bge-m3
SECRAG_EXPERIMENT=ctf_wiki_v1
```

## 准备与远程编码

远程作业包仅包含源码、依赖、来源清单和模型锁：

```powershell
.venv\Scripts\python.exe -X utf8 tools\pack_ctf_job.py artifacts\ctf-job.tar.gz
```

在已安装 CUDA 的 Linux 主机上解压后执行：

```bash
python -m venv .venv --system-site-packages
source .venv/bin/activate
pip install -r requirements-ctf-build.txt
python tools/run_ctf_remote.py --stage pilot --workdir /workspace/ctf-build --batch-size 8
python tools/run_ctf_remote.py --stage full --workdir /workspace/ctf-build --batch-size 8
```

`pilot` 用于验证 CUDA、切片、token 上限和代表性检索；`full` 使用同一来源和模型 revision 生成完整产物。两个阶段都不调用回答模型。

## 导入

将远程 `bundle-full-*` 目录下载到本地后，导入到一个尚不存在的实验目录：

```powershell
$env:SECRAG_EXPERIMENT='ctf_wiki_v1'
$env:EMBED_MODEL='BAAI/bge-m3'
.venv\Scripts\python.exe -m secrag.remote_build import --bundle data\bundle-ctf-v1
```

导入会校验文件哈希、来源 commit、模型 revision、向量维度、文档关联和原文重建。目标目录已存在时不会覆盖。

## 启动

```powershell
Set-Location web
pnpm install
pnpm run build
Set-Location ..
.venv\Scripts\python.exe -m secrag.web --port 8766
```

访问 `http://127.0.0.1:8766/`。如果知识库缺失或校验失败，页面会显示未就绪原因并禁止提问。

CLI 问答：

```powershell
.venv\Scripts\python.exe -m secrag.cli "RSA 小指数题应该先检查哪些条件？"
```

## 验证

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe tools\evaluate_ctf.py
Set-Location web
pnpm run build
```

`evaluate_ctf.py` 默认只列出固定案例。使用 `--retrieval` 或 `--live` 时才会加载本地知识库；`--live` 会调用配置的回答模型。输出 JSON 仅保存在本地，不提交到 Git。
