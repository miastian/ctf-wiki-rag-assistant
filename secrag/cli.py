"""CTF Wiki 思路助手命令行入口。"""
import argparse
import json

from secrag.config import EMBED_MODEL, PROCESSED_DIR


def load_chunks() -> list[dict]:
    with (PROCESSED_DIR / "chunks.jsonl").open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def make_retriever():
    from secrag.embedder import Embedder
    from secrag.library import validate_ctf_library, verified_local_model
    from secrag.retriever import Retriever
    from secrag.store import VectorStore
    from secrag.config import ROOT

    manifest = validate_ctf_library(PROCESSED_DIR)
    index_config = json.loads((PROCESSED_DIR / "index_manifest.json").read_text(encoding="utf-8"))
    if index_config["embedding_model"] != EMBED_MODEL:
        raise RuntimeError(
            f"索引使用 {index_config['embedding_model']}, 当前配置为 {EMBED_MODEL}; 请恢复配置或重新导入"
        )
    model_revision = index_config.get("model_revision")
    local_model = verified_local_model(ROOT, EMBED_MODEL, model_revision)
    embedder = Embedder(local_model) if local_model else Embedder(EMBED_MODEL, revision=model_revision)
    encoding = index_config.get("encoding", {})
    if encoding:
        embedder.model.max_seq_length = encoding["max_seq_length"]
    if embedder.dim != index_config["dimension"]:
        raise RuntimeError("查询 embedding 维度与 CTF 索引不一致")
    chunks, store = load_chunks(), VectorStore()
    if store.count() != len(chunks):
        raise RuntimeError("片段文件与向量索引数量不一致，请重新导入")
    return Retriever(chunks, store, embedder), manifest


def ask(question: str, retrieve_only: bool = False, show_trace: bool = False):
    retriever, manifest = make_retriever()
    if retrieve_only:
        hits, trace = retriever.retrieve(question, top_k=5)
        if show_trace:
            print(json.dumps(trace, ensure_ascii=False, indent=2))
        print(json.dumps(hits, ensure_ascii=False, indent=2))
        return

    from secrag.ctf_chat import CtfChatEngine
    from secrag.llm import ModelClient

    engine = CtfChatEngine(retriever, ModelClient(), manifest)
    for kind, data in engine.events(question, [], {"mode": "auto"}):
        if kind == "delta":
            print(data["text"], end="", flush=True)
        elif kind == "done":
            print()
            for source in data["sources"]:
                print(f"[{source['number']}] {source['title']} {source['url']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("question")
    parser.add_argument("--retrieve-only", action="store_true", help="只验证检索，不调用回答模型")
    parser.add_argument("--show-trace", action="store_true")
    args = parser.parse_args()
    try:
        ask(args.question, args.retrieve_only, args.show_trace)
    except RuntimeError as exc:
        raise SystemExit(f"错误: {exc}") from None


if __name__ == "__main__":
    main()
