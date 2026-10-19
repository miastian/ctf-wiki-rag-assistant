"""集中读取 .env 配置。"""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

EXPERIMENT = os.getenv("SECRAG_EXPERIMENT", "ctf_wiki_v1")
if not EXPERIMENT.startswith("ctf_"):
    raise ValueError("SECRAG_EXPERIMENT 必须以 ctf_ 开头")
if EXPERIMENT:
    if not all(c.isalnum() or c in "_-" for c in EXPERIMENT):
        raise ValueError("SECRAG_EXPERIMENT 只能包含字母、数字、下划线和连字符")
    PROCESSED_DIR = ROOT / "data" / "experiments" / EXPERIMENT
    CHROMA_DIR = ROOT / f"chroma_{EXPERIMENT}"

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "")
EMBED_MODEL = os.getenv("EMBED_MODEL", "BAAI/bge-m3")
RETRIEVAL_POOL = int(os.getenv("RETRIEVAL_POOL", "30"))
