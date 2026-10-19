"""Embedding 封装,默认使用中文模型 BAAI/bge-small-zh-v1.5。"""
from sentence_transformers import SentenceTransformer


class Embedder:
    def __init__(self, model_name: str = "BAAI/bge-small-zh-v1.5", batch_size: int = 32,
                 revision: str | None = None):
        self.model = SentenceTransformer(model_name, **({"revision": revision} if revision else {}))
        self.dim = self.model.get_embedding_dimension()
        self.batch_size = batch_size

    def embed(self, texts: list[str]) -> list[list[float]]:
        """批量 embedding,返回二维列表。"""
        if not texts:
            return []
        embeddings = self.model.encode(texts, batch_size=self.batch_size,
                                       convert_to_numpy=True, show_progress_bar=False)
        return embeddings.tolist()

    def embed_one(self, text: str) -> list[float]:
        """单条 embedding。"""
        return self.embed([text])[0]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self.embed(texts)

    def embed_query(self, text: str) -> list[float]:
        return self.embed_one(text)
