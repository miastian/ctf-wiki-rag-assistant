"""Bounded two-query recall within a single hard filter scope."""
import re

from secrag.retriever import rrf, tokenize


def retrieve_ctf(scoped, original, effective, quick=None, top_k=5):
    planned, plan_trace = scoped.retrieve(effective, 10)
    queries = [{'kind': 'effective', 'query': effective, 'trace': plan_trace}]
    # Short referential messages depend on the planner; code and named subjects
    # can instead preserve information lost or over-expanded by that planner.
    raw_query = re.sub(r'```.*?```|~~~.*?~~~', ' ', original, flags=re.S).strip()
    eligible = (not quick and bool(raw_query) and raw_query != effective and len(raw_query) <= 1000 and
                not re.search(r'第[一二三四五六七八九十0-9]+[点步项条]', original))
    raw, raw_trace = scoped.retrieve(raw_query, 10) if eligible else ([], {})
    generic = {'介绍','简介','基础','方法','常见','分析','攻击','原理','相关','题目',
               '刚才','之前','上一','假设','成立','还能','说的','这个','那个','问题',
               '说明','条件','结果','信息','判断','如何','怎么','哪些','代码','程序',
               '函数','数据','内容','文件','提供','检查','是否','什么','意思','当前',
               '漏洞','安全','输入','输出','应用','使用','开始','通用','步骤','了解',
               '一般','理解','解释','请问','知道','能否','可以','常用','主要','作用','一个'}
    subject_terms = [t for t in tokenize(raw_query)
                     if (len(t) > 1 or t in {'栈', '堆'}) and t not in generic]
    # Named Chinese subjects (e.g. 小指数/逆向) matter just as named formats do.
    # A referential phrase is safe to search when it still names its subject;
    # numbered-point references remain entirely dependent on their resolution.
    # Preserve the leading specific subject, not a broader trailing word:
    # "异或编码" must not become a named match for every "编码" introduction.
    primary_subject = subject_terms[0] if subject_terms else None
    named_chinese = primary_subject is not None and any(
        primary_subject in set(tokenize(h.get('title', ''))) for h in raw)
    independent = eligible and (bool(re.search(r'[a-zA-Z]{2,}', raw_query)) or named_chinese)
    if eligible and not independent:
        queries.insert(0, {'kind': 'original_probe_not_fused', 'query': raw_query, 'trace': raw_trace})
    if independent:
        queries.insert(0, {'kind': 'original', 'query': raw_query, 'trace': raw_trace})
        # Rank-only fusion; original subject has two votes, inferred expansion one.
        scores = rrf([[h['doc_id'] for h in raw], [h['doc_id'] for h in raw],
                      [h['doc_id'] for h in planned]])
        hits = {h['doc_id']: h for h in planned}
        hits.update({h['doc_id']: h for h in raw})
        candidates = [hits[doc] for doc in sorted(scores, key=scores.get, reverse=True)]
    else:
        candidates = planned
    return candidates[:top_k], {'route': 'ctf_two_query' if independent else 'ctf_effective_query',
        'query_runs': queries, 'top_k': top_k,
        'candidate_doc_ids': [h['doc_id'] for h in candidates],
        'selected_document_ids': [h['doc_id'] for h in candidates[:top_k]],
        'truncated_document_ids': [h['doc_id'] for h in candidates[top_k:]],
        'original_query_used': independent}
