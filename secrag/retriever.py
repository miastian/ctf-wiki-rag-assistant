"""检索:向量检索 / BM25 / 两者用 RRF 融合。

BM25 与向量检索使用同一份切片语料(chunks.jsonl),保证两路结果可以按 id 对齐融合。
"""
import re
from collections import OrderedDict

import jieba
from rank_bm25 import BM25Okapi


def tokenize(text: str) -> list[str]:
    """jieba 搜索引擎模式分词 + 编号整词。统一小写,并规范化编号格式。"""
    text_lower = text.lower()
    return [token for token in jieba.lcut_for_search(text_lower) if token.strip()]


def rrf(rankings: list[list[str]], k: int = 60) -> dict[str, float]:
    """倒数排名融合:score(d) = sum(1 / (k + rank)),rank 从 1 开始。只看名次,不看原始分数,
    所以不需要把余弦相似度和 BM25 分数归一化到同一尺度。"""
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, cid in enumerate(ranking, start=1):
            scores[cid] = scores.get(cid, 0.0) + 1.0 / (k + rank)
    return scores


class Retriever:
    MODES = ("vector", "bm25", "hybrid")

    def __init__(self, chunks: list[dict], store=None, embedder=None, reranker=None):
        self.by_id = {c["id"]: c for c in chunks}
        self.ids = [c["id"] for c in chunks]
        self.store, self.embedder = store, embedder
        self.reranker = reranker
        self._scopes = OrderedDict()
        self.by_doc = {}
        for chunk in chunks:
            self.by_doc.setdefault(chunk["doc_id"], []).append(chunk["id"])
        self.bm25 = BM25Okapi([tokenize(c.get("embedding_text", c["text"])) for c in chunks])

    def _hit(self, cid: str, score: float) -> dict:
        c = self.by_id[cid]
        return {"id": cid, "doc_id": c["doc_id"], "source": c["source"],
                "section": c.get("section", ""),
                "title": c["title"], "text": c["text"], "score": score,
                "lang": c.get("lang", ""), "meta": c.get("meta", {})}

    def scoped(self, sources=(), language=None, categories=()):
        """在召回前缩小语料；子检索器的编号、BM25和上下文均仅含合格片段。"""
        key = (tuple(sorted(set(sources))), language or None, tuple(sorted(set(categories))))
        if not key[0] and not key[1] and not key[2]:
            return self
        if key in self._scopes:
            self._scopes.move_to_end(key)
            return self._scopes[key]
        chunks = [c for c in self.by_id.values()
                  if (not key[0] or c["source"] in key[0])
                  and (not key[1] or c.get("lang") == key[1])
                  and (not key[2] or set(c.get('categories', [])) & set(key[2]))]
        if not chunks:
            return None
        clauses = []
        if key[0]:
            clauses.append({"source": {"$in": list(key[0])}})
        if key[1]:
            clauses.append({"lang": key[1]})
        if key[2]:
            choices = [{"category_" + c: True} for c in key[2]]
            clauses.append(choices[0] if len(choices) == 1 else {"$or": choices})
        where = clauses[0] if len(clauses) == 1 else {"$and": clauses}
        store = self.store
        class ScopedStore:
            def search(_, embedding, top_k=10):
                return store.search(embedding, min(top_k, len(chunks)), where=where)
        view = Retriever(chunks, ScopedStore() if store else None, self.embedder, self.reranker)
        self._scopes[key] = view
        if len(self._scopes) > 16:
            self._scopes.popitem(last=False)
        return view

    def search_vector(self, query: str, top_k: int) -> list[dict]:
        encoder = getattr(self.embedder, "embed_query", None) or self.embedder.embed_one
        hits = self.store.search(encoder(query), top_k=top_k)
        return [self._hit(h["id"], h["score"]) for h in hits]

    def search_bm25(self, query: str, top_k: int) -> list[dict]:
        scores = self.bm25.get_scores(tokenize(query))
        top = sorted(range(len(scores)), key=scores.__getitem__, reverse=True)[:top_k]
        return [self._hit(self.ids[i], float(scores[i])) for i in top if scores[i] > 0]

    def search(self, query: str, mode: str = "hybrid", top_k: int = 5, pool: int = 50) -> list[dict]:
        """mode: vector / bm25 / hybrid。hybrid 先从两路各取 pool 条候选再融合。"""
        if mode == "vector":
            return self.search_vector(query, top_k)
        if mode == "bm25":
            return self.search_bm25(query, top_k)
        if mode != "hybrid":
            raise ValueError(f"未知检索模式: {mode}")
        vec, kw = self.search_vector(query, pool), self.search_bm25(query, pool)
        fused = rrf([[h["id"] for h in vec], [h["id"] for h in kw]])
        ranked = sorted(fused.items(), key=lambda x: x[1], reverse=True)[:top_k]
        return [self._hit(cid, score) for cid, score in ranked]

    def retrieve(self, query: str, top_k: int = 5, pool: int = 30,
                 rerank_top_n: int = 20, use_rerank: bool | None = None,
                 candidate_limit: int | None = None) -> tuple[list[dict], dict]:
        """CTF 混合检索：向量与 BM25 召回后按文档去重。"""
        if top_k < 1 or pool < 1 or rerank_top_n < 1:
            raise ValueError("top_k、pool 和 rerank_top_n 必须大于0")
        rerank = self.reranker is not None if use_rerank is None else use_rerank
        if rerank and self.reranker is None:
            raise ValueError("启用重排需要加载 reranker")
        if candidate_limit is not None and candidate_limit < 1:
            raise ValueError("candidate_limit 必须大于0")
        if any(c['source'] != 'ctf-wiki' for c in self.by_id.values()):
            raise ValueError('CTF 检索器禁止混入其他资料')
        trace = {"route": "hybrid", "intent": "ctf", "reranked": False}
        vec = self.search_vector(query, pool)
        kw = self.search_bm25(query, pool)
        trace['queries'] = [{'query': query, 'pool': pool,
            'vector': [{'id': h['id'], 'score': h['score']} for h in vec],
            'bm25': [{'id': h['id'], 'score': h['score']} for h in kw]}]
        scores = rrf([[h["id"] for h in vec], [h["id"] for h in kw]])
        ranked = [self._hit(cid, score) for cid, score in
                  sorted(scores.items(), key=lambda item: item[1], reverse=True)]
        seen, candidates = set(), []
        for hit in ranked:
            if hit["doc_id"] not in seen:
                seen.add(hit["doc_id"])
                candidates.append(hit)
        limit = candidate_limit if candidate_limit is not None else (rerank_top_n if rerank else None)
        if limit is not None:
            candidates = candidates[:limit]
        trace['fusion_document_order'] = [h['doc_id'] for h in candidates]
        # Preserve explicit format/tool subjects even if generic introductory
        # pages outrank them. This is ranking within the scoped recall pool.
        def subject_match(hit):
            label = hit['title'] + ' ' + re.sub(r'[/_.:-]', ' ', hit['doc_id']) + ' ' + ' '.join(
                self.by_id[cid].get('section', '') for cid in self.by_doc[hit['doc_id']])
            atoms = re.findall(r'[a-z][a-z0-9+]{1,}', label.lower())
            generic_ascii = {'ctf', 'wiki', 'flag', 'example', 'introduction'}
            ascii_score = sum(bool(re.search(r'(?<![a-z0-9_])' + re.escape(atom) +
                                      r'(?![a-z0-9_])', query.lower())) for atom in set(atoms) - generic_ascii)
            generic = {'介绍', '简介', '基础', '方法', '常见', '分析', '攻击', '原理', '相关', '题目'}
            terms = {t for t in tokenize(hit['title']) if re.fullmatch(r'[\u4e00-\u9fff]{2,}|[栈堆]',t)} - generic
            chinese_score = len(terms & set(tokenize(query)))
            foundation = bool(re.search(r'基本|基础|定义|是什么|关系|加解密|起什么作用|有什么作用|用途|如何工作|怎么工作', query)) and (
                bool(re.search(r'简介|介绍|概述|(?:^|[/_-])intro(?:duction)?(?:[./_-]|$)',
                               hit['title'] + ' ' + hit['doc_id'])) or any(
                re.search(r'基本原理|定义', self.by_id[cid].get('section', ''))
                for cid in self.by_doc[hit['doc_id']]))
            return 10 * ascii_score + chinese_score + 2 * foundation
        candidates.sort(key=lambda h: -subject_match(h))
        trace["candidate_documents"] = len(candidates)
        trace["candidate_doc_ids"] = [hit["doc_id"] for hit in candidates]
        if rerank:
            candidates = self.reranker.rank(query, candidates)
            trace["reranked"] = True
        trace.update(top_k=top_k, selected_document_ids=[h['doc_id'] for h in candidates[:top_k]],
                     truncated_document_ids=[h['doc_id'] for h in candidates[top_k:]])
        return candidates[:top_k], trace
