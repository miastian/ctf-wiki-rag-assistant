"""Versioned CTF slicing with exact source offsets and resumable fenced code."""
import re

VERSION = 'ctf-v1'
FENCE = re.compile(r'^\s*(`{3,}|~{3,})(.*)$')
HEADING = re.compile(r'^(#{1,6})\s+(.+)')


def fence_after(text, active=None):
    for line in text.splitlines():
        match = FENCE.match(line)
        if not match:
            continue
        marker, suffix = match.groups()
        if active is None:
            active = (marker, suffix)
        elif marker[0] == active[0][0] and len(marker) >= len(active[0]) and not suffix.strip():
            active = None
    return active


def chunk_ctf(doc, max_chars=1800):
    if max_chars < 128:
        raise ValueError('CTF 片段预算过小')
    text, chunks, start, active, path = doc['text'], [], 0, None, []
    boundaries, heading_paths, offset, scan = [0], {0: ''}, 0, None
    for line in text.splitlines(keepends=True):
        heading = HEADING.match(line) if scan is None else None
        if heading:
            level = len(heading[1])
            while path and path[-1][0] >= level:
                path.pop()
            path.append((level, heading[2].strip()))
            if offset and not text[:offset].strip():
                heading_paths[0] = ' > '.join(title for _, title in path)
            elif offset not in boundaries:
                boundaries.append(offset)
            if offset in boundaries:
                heading_paths[offset] = ' > '.join(title for _, title in path)
        scan = fence_after(line, scan)
        offset += len(line)
    boundaries.append(len(text))
    section_index = 0
    while start < len(text):
        while section_index + 1 < len(boundaries) and start >= boundaries[section_index + 1]:
            section_index += 1
        section_end = boundaries[section_index + 1]
        limit = min(start + max_chars, section_end)
        end = limit
        if limit < section_end:
            # Prefer paragraph boundaries, then whole lines. Long individual lines
            # remain reconstructable via exact offsets rather than being dropped.
            candidates = [m.end() + start for m in re.finditer(r'\n\s*\n', text[start:limit])]
            candidates = [n for n in candidates if n > start + max_chars // 3]
            newline = text.rfind('\n', start, limit)
            end = candidates[-1] if candidates else (newline + 1 if newline > start else limit)
        raw = text[start:end]
        scan_active = fence_after(raw, active)
        section = heading_paths[boundaries[section_index]]
        rendered = ((active[0] + active[1] + '\n') if active else '') + raw
        if scan_active:
            rendered = rendered.rstrip('\n') + '\n' + scan_active[0] + '\n'
        header = doc['title'] + (' > ' + section if section else '')
        index = len(chunks)
        chunks.append({'id': f"{doc['id']}#{index}", 'doc_id': doc['id'],
                       'source': doc['source'], 'title': doc['title'], 'lang': doc['lang'],
                       'text': rendered, 'source_text': raw, 'embedding_text': header + '\n' + rendered,
                       'section': section, 'categories': doc.get('categories', []),
                       'ordinal': index, 'source_start': start, 'source_end': end,
                       'meta': {**doc.get('meta', {}), 'chunk_version': VERSION,
                                'continued_code': active is not None, 'continues_code': scan_active is not None}})
        start, active = end, scan_active
    if ''.join(c['source_text'] for c in chunks) != text:
        raise ValueError('CTF 切片正文覆盖核对失败')
    return chunks


def select_ctf_context(query, recalled, retriever, max_chars=16000, max_chunks=8):
    """Select method bundles within scoped documents, preserving complete slices."""
    from secrag.retriever import tokenize
    query_terms = set(tokenize(query)) - {'分析', '方法', '常见', '如何', '怎么', '什么', '哪些', '原理', '攻击'}
    query_terms = {t for t in query_terms if len(t) > 1}
    definition = bool(re.search(r'是什么|基本|基础|定义|关系|加解密|加密.*解密', query))
    broad = bool(re.search(r'常见|入手|开始|一般|哪些|流程|路线|思路|入口', query))
    candidates, reasons = [], {}

    def add(hit, reason):
        if hit['id'] not in reasons:
            candidates.append(hit)
            reasons[hit['id']] = reason

    def substantive(hit):
        return bool(re.sub(r'(?m)^\s*#{1,6}[^\n]*$', '', hit['text']).strip())

    for doc_index, anchor in enumerate(recalled):
        pool = [retriever._hit(cid, 0) for cid in retriever.by_doc[anchor['doc_id']]]
        useful = [h for h in pool if substantive(h)]
        def section_match(hit):
            # Root names are shared by all methods; match their child headings.
            parts = hit.get('section', '').split(' > ')
            local = ' '.join(parts[1:]) if len(parts) > 1 else parts[0]
            return len(query_terms & set(tokenize(local)))
        best = max(useful, key=lambda h: (section_match(h), h['id'] == anchor['id']), default=anchor)
        # A retrieved example must retain the definitions of its parent section.
        best_path = best.get('section', '').split(' > ')
        if doc_index == 0:
            for h in useful:
                path = h.get('section', '').split(' > ')
                if len(path) < len(best_path) and best_path[:len(path)] == path:
                    add(h, 'parent_definition')
            if re.search(r'字节|偏移|CRC|字段|宽高|结构', query, re.I):
                for h in useful:
                    if re.search(r'\|\s*(?:CRC|Length|Chunk Type)', h['text']) and re.search(r'字节|bytes', h['text'], re.I):
                        add(h, 'format_field_definition')
                        break
        if doc_index == 0:
            foundations = [h for h in useful if definition and re.search(
                r'基本原理|定义|消息加密|消息解密|密钥.*产生', h.get('section', ''))]
            for h in foundations[:4]:
                add(h, 'definition_foundation')
            # Bind the best matching method to its conditions and principle.
            parts = best.get('section', '').split(' > ')
            parent = ' > '.join(parts[:-1])
            for h in useful:
                section = h.get('section', '')
                if parent and section.startswith(parent + ' > ') and re.search(
                        r'条件|原理|步骤|限制|注意|定义', section.split(' > ')[-1]):
                    add(h, 'method_conditions_principle')
            if broad and not foundations:
                groups = {}
                for h in useful:
                    parts = h.get('section', '').split(' > ')
                    group = parts[1] if len(parts) > 1 else parts[0]
                    groups.setdefault(group, []).append(h)
                for group in groups.values():
                    add(min(group, key=lambda h: (h.get('section', '').count(' > '), len(h['text']))),
                        'method_overview')
                    if len(candidates) >= 4:
                        break
                diagnostics = sorted(useful, key=lambda h: -len(re.findall(
                    r'检查|异常|错误|error|经常|步骤|条件|原理', h['text'], re.I)))
                for h in diagnostics[:2]:
                    add(h, 'diagnostic_condition')
            # A follow-up may name several methods without saying "common".
            # Keep a relevant representative of each matching method group,
            # instead of letting a tied IHDR anchor hide the same PNG's LSB.
            matched_groups = {}
            for h in useful:
                parts = h.get('section', '').split(' > ')
                group = parts[1] if len(parts) > 1 else parts[0]
                if section_match(h):
                    matched_groups.setdefault(group, []).append(h)
            ranked_groups = sorted(matched_groups.values(),
                                   key=lambda group: -max(section_match(h) for h in group))
            for group in ranked_groups[:3]:
                add(max(group, key=lambda h: (section_match(h), -h.get('section', '').count(' > '),
                                              -len(h['text']))), 'explicit_method_group')
        add(best, 'query_section_match' if best['id'] != anchor['id'] else 'recall_anchor')
        if substantive(anchor):
            add(anchor, 'recall_anchor')
    # A fenced code sequence is an atomic evidence unit. Recover both earlier
    # and later slices when recall starts in the middle, using this scope only.
    def code_bundle(hit):
        original = retriever.by_id[hit['id']]
        if not (original.get('meta', {}).get('continued_code') or
                original.get('meta', {}).get('continues_code')):
            return [hit]
        ordinals = {retriever.by_id[cid].get('ordinal'): cid
                    for cid in retriever.by_doc[hit['doc_id']]}
        ordinal = original.get('ordinal')
        if not isinstance(ordinal, int):
            return []
        start = ordinal
        while retriever.by_id[ordinals[start]].get('meta', {}).get('continued_code'):
            start -= 1
            if start not in ordinals:
                return []
        sequence = []
        while True:
            cid = ordinals[start]
            sequence.append(retriever._hit(cid, hit.get('score', 0)))
            if not retriever.by_id[cid].get('meta', {}).get('continues_code'):
                return sequence
            start += 1
            if start not in ordinals:
                return []

    selected, used, skipped, selected_ids = [], 0, [], set()
    skip_reasons = {}
    for hit in candidates:
        if hit['id'] in selected_ids:
            continue
        # Every selected example needs its own parent premises, even when it
        # is not the highest matching method or comes from a later document.
        # Dependencies and code continuations are one atomic evidence bundle.
        path = hit.get('section', '').split(' > ')
        parent = path[:-1]
        dependencies = []
        for cid in retriever.by_doc[hit['doc_id']]:
            related = retriever._hit(cid, 0)
            parts = related.get('section', '').split(' > ')
            ancestor = len(parts) < len(path) and path[:len(parts)] == parts
            premise = bool(parent and parts[:-1] == parent and re.search(
                r'条件|原理|限制|注意|定义', parts[-1]))
            if substantive(related) and (ancestor or premise):
                dependencies.append(related)
        bundle, bundle_ids = [], set()
        for required in dependencies + [hit]:
            chain = code_bundle(required)
            if not chain:
                bundle = []
                break
            for part in chain:
                if part['id'] not in bundle_ids:
                    bundle.append(part)
                    bundle_ids.add(part['id'])
                    if part['id'] != hit['id']:
                        reasons.setdefault(part['id'], 'method_dependency')
        additions = [h for h in bundle if h['id'] not in selected_ids]
        cost = sum(len(h['text']) + len(h.get('section', '')) + 100 for h in additions)
        if bundle and len(selected) + len(additions) <= max_chunks and used + cost <= max_chars:
            for h in additions:
                selected.append(h)
                selected_ids.add(h['id'])
                reasons.setdefault(h['id'], 'code_continuation')
            used += cost
        else:
            skipped.append(hit['id'])
            skip_reasons[hit['id']] = 'incomplete_code_chain' if not bundle else 'whole_evidence_budget'
    return selected, {'selected_chunk_ids': [h['id'] for h in selected], 'context_chars': used,
                      'omitted_chunks': len(skipped), 'skipped_chunk_ids': skipped,
                      'skip_reasons': skip_reasons,
                      'selection_reasons': {h['id']: reasons[h['id']] for h in selected},
                      'strategy': 'ctf-context-v3', 'max_chars': max_chars, 'max_chunks': max_chunks}
