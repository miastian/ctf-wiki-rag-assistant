"""远程 GPU 执行 export；下载产物后本地 import，不在本地切片或编码。"""
import argparse
import hashlib
import json
import re
import time
from pathlib import Path

import numpy as np


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify_ctf_coverage(docs, coverage, lock):
    """A full-coverage flag is valid only with a closed source-page ledger."""
    if coverage.get('commit') != lock.get('commit') or coverage.get('errors') or coverage.get('missing_navigation'):
        raise ValueError('CTF 来源版本或覆盖报告无效')
    if coverage.get('prepared') != len(docs):
        raise ValueError('CTF 已处理文档数量不一致')
    pages = coverage.get('pages')
    if not isinstance(pages, list) or not pages:
        raise ValueError('CTF 缺少原始页面清单')
    prepared = {p['path'] for p in pages if p['status'] == 'prepared'}
    if prepared != {d['meta']['path'] for d in docs}:
        raise ValueError('CTF 文档与原始页面清单不一致')
    if coverage.get('complete') and (coverage.get('sample') or any(p['status'] != 'prepared' for p in pages if not p.get('reason'))):
        raise ValueError('CTF 仍有未入库页面，不能标记完整')
    for doc in docs:
        if doc['meta'].get('version') != lock['commit']:
            raise ValueError('CTF 文档版本不一致')


def export_bundle(docs_path, output, model, revision, batch=8, device="cuda", strategy="source", model_path=None):
    started = time.perf_counter()
    if batch < 1 or not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        raise ValueError("batch 必须为正数，revision 必须为40位模型 commit SHA")
    from sentence_transformers import SentenceTransformer
    from secrag.ctf_chunker import chunk_ctf
    output = Path(output)
    if output.exists():
        raise ValueError("产物目录已存在，请使用新的目录；共享缓存可复用")
    docs = [json.loads(line) for line in Path(docs_path).read_text(encoding="utf-8").splitlines() if line.strip()]
    if not docs or len({d["id"] for d in docs}) != len(docs):
        raise ValueError("语料为空或文档 ID 重复")
    if strategy != 'ctf':
        raise ValueError('当前仅支持 CTF 切片策略')
    if any(d.get('source') != 'ctf-wiki' for d in docs):
        raise ValueError('CTF 产物禁止混入旧资料')
    prepared = Path(docs_path).parent
    verify_ctf_coverage(docs, json.loads((prepared / 'coverage.json').read_text(encoding='utf-8')),
                        json.loads((prepared / 'source-lock.json').read_text(encoding='utf-8')))
    chunks = [c for d in docs for c in chunk_ctf(d)]
    if not chunks or any(not c["text"].strip() for c in chunks):
        raise ValueError("存在空片段")
    encoder = SentenceTransformer(model_path, device=device) if model_path else SentenceTransformer(model, revision=revision, device=device)
    texts = [c.get('embedding_text', c['text']) for c in chunks]
    if strategy == 'ctf':
        for text in texts:
            if len(encoder.tokenizer.encode(text, add_special_tokens=True, truncation=False)) > encoder.max_seq_length:
                raise ValueError('片段超过模型 token 上限，需调整切片，禁止静默截断')
    config = {"model": model, "revision": revision,
              "max_seq_length": encoder.max_seq_length, "normalize_embeddings": False}
    cache = output.parent / "vector_cache" / hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    cache.mkdir(parents=True, exist_ok=True)
    vectors = [None] * len(chunks)
    keys = [hashlib.sha256(t.encode()).hexdigest() for t in texts]
    missing = []
    for i, key in enumerate(keys):
        path = cache / (key + ".npy")
        if path.exists():
            vector = np.load(path, allow_pickle=False)
            if vector.shape != (encoder.get_sentence_embedding_dimension(),) or not np.isfinite(vector).all():
                raise ValueError("向量缓存损坏")
            vectors[i] = vector
        else:
            missing.append(i)
    for start in range(0, len(missing), batch):
        indices = missing[start:start + batch]
        encoded = encoder.encode([texts[i] for i in indices], batch_size=batch,
                                 convert_to_numpy=True, normalize_embeddings=False)
        for i, vector in zip(indices, encoded):
            vectors[i] = vector
            temporary = cache / (keys[i] + ".tmp.npy")
            np.save(temporary, vector, allow_pickle=False)
            temporary.replace(cache / (keys[i] + ".npy"))
        print(f"新增编码 {min(start + batch, len(missing))}/{len(missing)}", flush=True)
    output.mkdir(parents=True)
    (output / "chunks.jsonl").write_text("".join(json.dumps(c, ensure_ascii=False) + "\n" for c in chunks), encoding="utf-8")
    np.save(output / "vectors.npy", np.asarray(vectors, dtype=np.float32), allow_pickle=False)
    manifest = {"schema_version": 1, "embedding_model": model, "model_revision": revision,
                "encoding": config, "chunk_strategy": "source", "documents": len(docs),
                "chunks": len(chunks), "dimension": int(vectors[0].shape[0]),
                "files": {name: digest(output / name) for name in ("chunks.jsonl", "vectors.npy")}}
    if strategy == 'ctf':
        from shutil import copyfile, copytree
        prepared = Path(docs_path).parent
        coverage = json.loads((prepared / 'coverage.json').read_text(encoding='utf-8'))
        for doc in docs:
            parts = sorted((c for c in chunks if c['doc_id'] == doc['id']), key=lambda c: c['ordinal'])
            if ''.join(c['source_text'] for c in parts) != doc['text']:
                raise ValueError('原文与片段完整性不一致')
        coverage.update(indexed_documents=len(docs), indexed_chunks=len(chunks), source_reconstruction_verified=True)
        (output / 'coverage.json').write_text(json.dumps(coverage, ensure_ascii=False, indent=2), encoding='utf-8')
        for name in ('docs.jsonl', 'source-lock.json', 'LICENSE'):
            copyfile(prepared / name, output / name)
        if (prepared / 'assets').is_dir():
            copytree(prepared / 'assets', output / 'assets')
        manifest.update(schema_version=2, profile='ctf', chunk_strategy='ctf', chunk_version='ctf-v1',
                        source_commit=coverage['commit'], complete=coverage['complete'],
                        files={p.relative_to(output).as_posix(): digest(p) for p in output.rglob('*') if p.is_file()})
    manifest['build_seconds'] = round(time.perf_counter() - started, 3)
    manifest['new_vectors'], manifest['cached_vectors'] = len(missing), len(chunks) - len(missing)
    (output / "index_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"完成：{len(chunks)} 片段，新增 {len(missing)}，缓存复用 {len(chunks) - len(missing)}")


def import_bundle(bundle):
    from secrag.config import PROCESSED_DIR, CHROMA_DIR
    from secrag.store import VectorStore
    bundle = Path(bundle)
    manifest = json.loads((bundle / "index_manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") not in (1, 2):
        raise ValueError("不支持的产物格式")
    if manifest.get('schema_version') != 2:
        raise ValueError('仅支持 CTF schema v2 产物')
    for name in manifest["files"]:
        target = (bundle / name).resolve()
        if not target.is_relative_to(bundle.resolve()):
            raise ValueError('产物路径越界')
        if digest(bundle / name) != manifest["files"][name]:
            raise ValueError(f"校验失败：{name}")
    chunks = [json.loads(line) for line in (bundle / "chunks.jsonl").read_text(encoding="utf-8").splitlines()]
    vectors = np.load(bundle / "vectors.npy", allow_pickle=False)
    if (vectors.shape != (len(chunks), manifest["dimension"]) or not np.isfinite(vectors).all()
            or len(chunks) != manifest["chunks"] or len({c["id"] for c in chunks}) != len(chunks)):
        raise ValueError("片段或向量不一致")
    if manifest.get('schema_version') == 2:
        required = {'docs.jsonl', 'source-lock.json', 'coverage.json', 'LICENSE', 'chunks.jsonl', 'vectors.npy'}
        if not required <= set(manifest['files']):
            raise ValueError('CTF 产物缺少必需文件')
        docs = [json.loads(line) for line in (bundle / 'docs.jsonl').read_text(encoding='utf-8').splitlines()]
        by_doc = {d['id']: d for d in docs}
        coverage = json.loads((bundle / 'coverage.json').read_text(encoding='utf-8'))
        lock = json.loads((bundle / 'source-lock.json').read_text(encoding='utf-8'))
        verify_ctf_coverage(docs, coverage, lock)
        if coverage.get('complete') != manifest.get('complete') or manifest.get('source_commit') != lock['commit']:
            raise ValueError('CTF manifest 与来源清单不一致')
        if len(by_doc) != len(docs) or len(docs) != manifest['documents']:
            raise ValueError('文档数量不一致')
        if any(c['doc_id'] not in by_doc or c['source'] != 'ctf-wiki' for c in chunks):
            raise ValueError('文档关联或来源不一致')
        for doc in docs:
            parts = sorted((c for c in chunks if c['doc_id'] == doc['id']), key=lambda c: c['ordinal'])
            if ''.join(c['source_text'] for c in parts) != doc['text']:
                raise ValueError('原文与片段不一致')
    if PROCESSED_DIR.exists() or CHROMA_DIR.exists():
        raise ValueError("目标已存在；设置全新的 SECRAG_EXPERIMENT，禁止覆盖旧索引")
    store = VectorStore()
    store.add(chunks, vectors.tolist())
    PROCESSED_DIR.mkdir(parents=True)
    (PROCESSED_DIR / "chunks.jsonl").write_bytes((bundle / "chunks.jsonl").read_bytes())
    if manifest.get('schema_version') == 2:
        from shutil import copyfile
        for name in manifest['files']:
            if name in ('chunks.jsonl', 'vectors.npy'):
                continue
            target = PROCESSED_DIR / name
            target.parent.mkdir(parents=True, exist_ok=True)
            copyfile(bundle / name, target)
    (PROCESSED_DIR / "index_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"导入完成：{store.count()} 个向量；尚未自动切换默认索引")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("export")
    export.add_argument("--docs", required=True)
    export.add_argument("--output", required=True)
    export.add_argument("--model", default="BAAI/bge-m3")
    export.add_argument("--revision", required=True, help="模型仓库 commit，确保本地查询使用同一版本")
    export.add_argument("--batch-size", type=int, default=8)
    export.add_argument("--device", default="cuda")
    export.add_argument('--strategy', choices=['ctf'], default='ctf')
    imp = sub.add_parser("import")
    imp.add_argument("--bundle", required=True)
    args = parser.parse_args()
    if args.command == "export":
        if args.batch_size < 1:
            parser.error("batch-size 必须大于0")
        export_bundle(args.docs, args.output, args.model, args.revision, args.batch_size, args.device, args.strategy)
    else:
        import_bundle(args.bundle)


if __name__ == "__main__":
    main()
