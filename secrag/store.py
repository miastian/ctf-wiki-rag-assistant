"""ChromaDB 封装:建库、插入片段、向量检索。"""
import chromadb
from chromadb.config import Settings

from secrag.config import CHROMA_DIR


class VectorStore:
    def __init__(self, persist_dir=CHROMA_DIR, name: str = "secrag", reset: bool = False):
        self.client = chromadb.PersistentClient(
            path=str(persist_dir), settings=Settings(anonymized_telemetry=False))
        if reset:
            try:
                self.client.delete_collection(name)
            except Exception:
                pass
        # 用余弦距离;embedding 由我们自己算好传入,不用 chroma 内置的。
        # HNSW 默认参数(ef 100 / M 16)在本库上只找回约 80% 的真实 top40,且每次建库结果不同,
        # 评测数字会随重建漂移。调高后召回约 0.997,建索引只多约 1 秒。见 docs/pitfalls.md 第 3 条。
        self.col = self.client.get_or_create_collection(name, configuration={"hnsw": {
            "space": "cosine", "ef_construction": 400, "ef_search": 400, "max_neighbors": 32}})

    def add(self, chunks: list[dict], embeddings: list[list[float]], batch: int = 2000):
        """分批写入。chunk 的 id/text 单独存放,其余字段作为 metadata。"""
        for i in range(0, len(chunks), batch):
            cs = chunks[i:i + batch]
            self.col.add(
                ids=[c["id"] for c in cs],
                documents=[c["text"] for c in cs],
                embeddings=embeddings[i:i + batch],
                metadatas=[{**{k: v for k, v in c.items() if k not in ("id", "text", "source_text", "embedding_text")
                            and isinstance(v, (str, int, float, bool))},
                            **{"category_" + name: True for name in c.get('categories', [])}} for c in cs],
            )

    def search(self, query_embedding: list[float], top_k: int = 10, where=None) -> list[dict]:
        r = self.col.query(query_embeddings=[query_embedding], n_results=min(top_k, self.count()),
                           **({"where": where} if where else {}))
        return [{"id": r["ids"][0][i], "text": r["documents"][0][i],
                 "score": 1 - r["distances"][0][i], "metadata": r["metadatas"][0][i]}
                for i in range(len(r["ids"][0]))]

    def count(self) -> int:
        return self.col.count()
