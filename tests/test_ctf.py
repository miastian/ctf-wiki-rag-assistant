import hashlib
import json
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from secrag.ctf_chunker import chunk_ctf, select_ctf_context
from secrag.ctf_chat import CtfChatEngine, valid_state
from secrag.ctf_wiki import inventory, prepare, write_json
from secrag.retriever import Retriever
from secrag.web import create_app


def document(key='misc/png.md', text=None, categories=None):
    return {'id': 'ctf-wiki:' + key, 'source': 'ctf-wiki', 'title': 'PNG 检查', 'lang': 'zh',
            'text': text or '# PNG\n检查 IHDR 和 CRC，观察宽高。\n## 代码\n```python\nprint("检查")\n```\n',
            'categories': categories or ['misc'], 'meta': {'url': 'https://ctf-wiki.org/misc/picture/png/',
                                                        'version': 'a' * 40, 'path': key}}


class Encoder:
    def embed_query(self, query):
        return [1.0, 0.0]


class Vector:
    def __init__(self, chunks):
        self.chunks, self.calls = chunks, []

    def search(self, vector, top_k=5, where=None):
        self.calls.append(where)
        def match(c, expr):
            if not expr:
                return True
            if '$and' in expr:
                return all(match(c, e) for e in expr['$and'])
            if '$or' in expr:
                return any(match(c, e) for e in expr['$or'])
            for key, value in expr.items():
                actual = key[9:] in c.get('categories', []) if key.startswith('category_') else c.get(key)
                if isinstance(value, dict):
                    return actual in value['$in']
                return actual == value
        return [{'id': c['id'], 'score': 1} for c in self.chunks if match(c, where)][:top_k]


class Model:
    def __init__(self):
        self.plans, self.answers, self.drafts = [], [], []
        self.transform = None
        self.response = '根据你贴出的结果，先检查 IHDR 字段，再验证假设。[1]'

    def complete(self, messages):
        payload = json.loads(messages[-1]['content'])
        if payload.get('generation_phase') == 'draft':
            self.drafts.append(payload)
            return self.response
        self.plans.append(payload)
        plan = {'action': 'answer', 'query': 'PNG IHDR CRC 检查', 'mode': 'next', 'intent': 'challenge',
                'state': {'challenge': 'PNG', 'observations': [{'text': payload['question'], 'message_id': payload['current_message_id']}],
                          'attempts': [], 'hypotheses': ['宽高可能异常，待验证'], 'material_ids': [payload['current_message_id']]}}
        if self.transform:
            self.transform(plan, payload)
        return json.dumps(plan, ensure_ascii=False)

    def stream(self, messages):
        self.answers.append(json.loads(messages[-1]['content']))
        yield self.response


def engine():
    cs = chunk_ctf(document()) + chunk_ctf(document('web/sqli.md', '# SQL\nSQL 注入条件。', ['web']))
    return CtfChatEngine(Retriever(cs, Vector(cs), Encoder()), Model())


def run(e, question, history=None, **settings):
    return next(data for kind, data in e.events(question, history or [], {'mode': 'auto', **settings}) if kind == 'done')


@pytest.mark.parametrize('question', ['帮我联网访问这个题目', '读取我没有上传的图片'])
def test_text_only_capability_requests_do_not_call_model(question):
    e = engine()
    result = run(e, question)
    assert result['action'] == 'clarify' and '不能' in result['answer']
    assert not e.model.plans and not e.model.answers


def test_placeholder_page_returns_saved_source_and_respects_scope():
    doc = document('reverse/ghidra.md', '# Ghidra\n', ['reverse'])
    doc['title'] = 'Ghidra'
    cs = chunk_ctf(doc)
    e = CtfChatEngine(Retriever(cs, Vector(cs), Encoder()), Model())
    result = run(e, '仅依据 Ghidra 专页介绍操作步骤')
    assert '占位' in result['answer'] and result['sources'][0]['doc_id'] == doc['id']
    assert not e.model.plans
    scoped = run(e, '仅依据 Ghidra 专页介绍操作步骤', categories=['web'])
    assert scoped['sources'] == [] and len(e.model.plans) == 1


def test_clarification_does_not_request_unavailable_upload_or_credentials():
    e = engine()
    e.model.transform = lambda p, q: p.update(action='clarify', reply='请提供账号密码和截图')
    result = run(e, '请分析这个题')
    assert '请粘贴' in result['answer'] and '账号密码' not in result['answer']


def test_latest_tool_parameters_require_version_text_without_model_call():
    e = engine()
    result = run(e, '按 CTF Wiki 说明今天最新版本工具的全部新参数。')
    assert result['action'] == 'clarify' and '固定版本' in result['answer']
    assert not e.model.plans


def saved(question, result):
    return {'id': result['message_id'], 'status': 'complete', 'question': question, 'answer': result['answer'], 'result': result}


def test_reference_answer_is_available_but_not_wiki_evidence():
    e = engine()
    first = run(e, 'PNG 检查')
    run(e, '第二点是什么意思？', [saved('PNG 检查', first)])
    assert e.model.answers[-1]['previous_answer_for_reference_only'] == first['answer']
    assert all('number' in row for row in e.model.answers[-1]['wiki_evidence'])


def test_summary_after_correction_clarification_uses_validated_state():
    e = engine()
    first = run(e, 'PNG 可以打开')
    first['action'] = 'clarify'
    result = run(e, '总结已尝试的方法', [saved('PNG 可以打开', first)], quick='summary')
    assert result['action'] == 'answer'
    assert e.model.answers[-1]['state']['attempts'] == []


@pytest.mark.parametrize('query,intent', [('', 'challenge'), (None, None), ('旧题CRC错误', 'invalid')])
def test_summary_after_clarification_uses_corrected_subject_even_without_query(query,intent):
    e=engine()
    correction='我说错了，当前图片正常；报错的是另一个文件。'
    first=run(e,correction)
    first.update(action='clarify',query=query,intent=intent)
    first['state'].update(challenge='另一个文件报错，格式未知',attempts=[])
    plan_count=len(e.model.plans)
    result=run(e,'总结已尝试的方法',[saved(correction,first)],quick='summary')
    assert result['action']=='answer' and result['query']=='另一个文件报错，格式未知'
    assert result['intent']=='challenge'
    assert result['state']==first['state'] and result['state']['attempts']==[]
    assert len(e.model.plans)==plan_count
    assert e.model.answers[-1]['state']['observations'][0]['text']==correction


def test_next_after_clarification_preserves_specific_pending_questions():
    e = engine()
    first = run(e, '环境版本还不确定')
    first.update(action='clarify')
    first['state']['pending'] = ['请确认 glibc 具体版本']
    before = len(e.model.plans)
    result = run(e, '下一步怎么做', [saved('环境版本还不确定', first)], quick='next')
    assert 'glibc' in result['answer'] and result['action'] == 'clarify'
    assert len(e.model.plans) == before


def test_inventory_covers_unnavigated_pages_and_normalizes_navigation():
    lock = {'docs_root': 'docs/zh/docs', 'repository': 'https://github.com/ctf-wiki/ctf-wiki', 'commit': 'a' * 40}
    entries = [{'path': 'docs/zh/docs/' + p, 'type': 'blob'} for p in ('index.md', 'misc/a.md', 'reverse/unlisted.md')]
    result = inventory(entries, {'nav': [{'Misc': ['misc//a.md']}, {'Web': ['web/missing.md']}]}, lock)
    assert result['missing_navigation'] == ['web/missing.md']
    assert result['counts'] == {'excluded': 1, 'pending': 2}
    assert result['pages'][-1]['in_navigation'] is False


def test_inventory_explicitly_reports_upstream_empty_placeholders():
    result=inventory([{'path':'docs/zh/docs/reverse/empty.md','type':'blob','size':0}],
                     {'nav':[{'Reverse':['reverse/empty.md']}]},
                     {'docs_root':'docs/zh/docs','repository':'https://github.com/ctf-wiki/ctf-wiki','commit':'a'*40})
    assert result['pages'][0]['status']=='excluded'
    assert 'empty placeholder' in result['pages'][0]['reason']
    assert not result['missing_navigation']


def test_remote_prepare_preserves_source_and_rejects_modified_snapshot(tmp_path, monkeypatch):
    repo, metadata, out = tmp_path/'repo', tmp_path/'meta', tmp_path/'out'
    root = repo/'docs/zh/docs/misc'; root.mkdir(parents=True); metadata.mkdir()
    raw = b'# PNG\n\n| A | B |\n|---|---|\n| 1 | 2 |\n'
    (root/'a.md').write_bytes(raw)
    blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    lock = {'docs_root': 'docs/zh/docs', 'repository': 'https://github.com/ctf-wiki/ctf-wiki', 'commit': 'a'*40, 'license': 'CC-BY-NC-SA-4.0'}
    write_json(metadata/'source-lock.json', lock)
    write_json(metadata/'upstream-tree.json', {'tree': [{'type': 'blob', 'path': 'docs/zh/docs/misc/a.md', 'sha': blob}]})
    (metadata/'mkdocs.yml').write_text('nav:\n- Misc:\n  - misc/a.md\n', encoding='utf-8')
    (metadata/'LICENSE').write_text('license')
    monkeypatch.setattr('subprocess.check_output', lambda *a, **k: 'a'*40)
    report = prepare(repo, metadata, out)
    assert report['complete'] and report['prepared'] == 1
    assert json.loads((out/'docs.jsonl').read_text())['text'].encode() == raw
    (root/'a.md').write_bytes(raw + b'modified')
    with pytest.raises(ValueError, match='处理失败'):
        prepare(repo, metadata, tmp_path/'bad')
    assert json.loads((tmp_path/'bad/coverage.json').read_text(encoding='utf-8'))['errors']


def test_slices_reconstruct_long_code_and_keep_fences_and_heading_paths():
    text = '# 测试\n段落\n## Python\n~~~~python\n' + ''.join(f'print({i})\n' for i in range(500)) + '~~~~\n## 表格\n| A | B |\n|---|---|\n| 1 | 2 |\n'
    cs = chunk_ctf(document(text=text), max_chars=250)
    assert ''.join(c['source_text'] for c in cs) == text
    assert all(text[c['source_start']:c['source_end']] == c['source_text'] for c in cs)
    assert any(c['meta']['continued_code'] for c in cs)
    assert all(c['text'].count('~~~~') % 2 == 0 for c in cs)
    assert cs[-1]['section'] == '测试 > 表格'
    assert all(len(c['source_text']) <= 250 for c in cs)


def test_leading_whitespace_does_not_create_empty_ctf_slice():
    doc=document(text='\n\n# PNG\n正文\n## IHDR\n检查内容\n')
    cs=chunk_ctf(doc)
    assert all(c['text'].strip() for c in cs)
    assert ''.join(c['source_text'] for c in cs)==doc['text']
    assert cs[0]['section']=='PNG'


def test_broad_method_context_includes_other_sections_not_only_tool_anchor():
    doc=document(text='# PNG\n## 文件格式\nPNG 文件有固定文件头。\n### IHDR\n宽高异常时检查 IHDR，CRC error 是线索。\n## LSB\n低位隐写可检查像素低位。\n## 隐写软件\nStepic 工具链接。\n')
    cs=chunk_ctf(doc);r=Retriever(cs)
    anchor=next(r._hit(c['id'],1) for c in cs if c['section'].endswith('隐写软件'))
    hits,_=select_ctf_context('PNG 隐写题一般先检查什么',[anchor],r)
    assert any(h['section'].endswith('LSB') for h in hits)
    assert any(h['section'].endswith('IHDR') for h in hits)


def test_real_chroma_category_filter_and_identifier_route_do_not_escape(tmp_path):
    from secrag.store import VectorStore
    cs = chunk_ctf(document()) + chunk_ctf(document('web/sqli.md', '# SQL\nSQL 漏洞。', ['web']))
    store = VectorStore(tmp_path/'index'); store.add(cs, [[1.0,0.0]] * len(cs))
    r = Retriever(cs, store, Encoder())
    view = r.scoped(categories=['web'])
    hits, trace = view.retrieve('CVE-2024-12345 SQL')
    assert hits and trace['route'] == 'hybrid'
    assert all(h['doc_id'].endswith('web/sqli.md') for h in hits)
    chosen, _ = select_ctf_context('SQL', hits, view)
    assert all(h['source'] == 'ctf-wiki' and h['doc_id'].endswith('web/sqli.md') for h in chosen)
    assert r.scoped(categories=['missing']) is None
    assert r.scoped(categories=['web']) is view
    assert {h['doc_id'] for h in r.scoped(categories=['misc','web']).search_vector('x', 100)} == {c['doc_id'] for c in cs}


def test_first_turn_understands_materials_and_snapshots_actual_evidence():
    e = engine(); result = run(e, '工具提示 IHDR CRC error', categories=['misc'], mode='checklist')
    assert e.model.plans[0]['question'] == '工具提示 IHDR CRC error'
    assert result['mode'] == 'checklist' and result['sources'][0]['version'] == 'a'*40
    assert result['sources'][0]['text'] in {c['text'] for c in e.retriever.by_id.values()}
    sent = e.model.answers[0]
    assert sent['detail'] == 'hints' and sent['user_materials'][0]['text'] == '工具提示 IHDR CRC error'


def test_quick_steps_preserves_raw_material_and_new_topic_resets_detail():
    e = engine(); first = run(e, '```python\na = [99]\n```')
    history = [saved('```python\na = [99]\n```', first)]
    second = run(e, '展开详细步骤', history, quick='steps')
    assert len(e.model.plans) == 1 and second['detail'] == 'steps'
    assert any('a = [99]' in m['text'] for m in e.model.answers[-1]['user_materials'])
    third = run(e, '换题，SQL 注入怎么入手', history+[saved('展开详细步骤', second)])
    assert third['detail'] == 'hints'
    assert len(e.model.plans[-1]['available_material_ids']) == 1


def test_observations_cannot_be_assistant_hypotheses_or_old_failed_material():
    with pytest.raises(RuntimeError, match='原文'):
        valid_state({'observations': [{'text': '已执行并找到flag', 'message_id': 'one'}]}, {'one': '尚未执行'})
    e=engine()
    e.model.transform=lambda p, q: p['state'].update(observations=[{'text':'观察', 'message_id':'failed'}])
    with pytest.raises(RuntimeError, match='原文'):
        run(e, 'IHDR', [{'id':'failed', 'status':'failed', 'question':'观察', 'answer':'残缺', 'result':{}}])


def test_material_outside_recent_window_is_resolvable_but_answer_not_evidence():
    e=engine(); q='```python\nprint("original")\n```'; first=run(e,q)
    history=[saved(q, first)]
    for i in range(7):
        result=run(e,f'第{i}次结果 CRC',history); history.append(saved(f'第{i}次结果 CRC',result))
    e.model.transform=lambda p,q: p['state'].update(material_ids=[first['message_id']])
    run(e, '请回看最初代码', history)
    assert len(e.model.plans[-1]['history']) == 6
    assert any(m['text']==q for m in e.model.answers[-1]['user_materials'])
    assert 'answer_excerpt_for_reference_only' not in e.model.answers[-1]


def test_empty_scope_never_generates_or_falls_back():
    e=engine(); result=run(e, 'IHDR', categories=['missing'])
    assert '不会自动扩大' in result['answer'] and not e.model.answers and not result['sources']


def test_next_turn_after_switch_cannot_revive_previous_challenge_material():
    e=engine(); first=run(e, 'PNG IHDR CRC error')
    h=[saved('PNG IHDR CRC error',first)]
    second=run(e, '换题，现在是 SQL',h);h.append(saved('换题，现在是 SQL',second))
    e.model.transform=lambda p,q:p['state'].update(material_ids=[first['message_id']])
    with pytest.raises(RuntimeError,match='材料引用无效'):
        run(e,'再分析一下',h)


def test_evaluation_contract_covers_all_source_directions_without_claiming_review():
    root=Path(__file__).resolve().parents[1]
    cases=json.loads((root/'data/eval/ctf_cases.json').read_text(encoding='utf-8'))
    inv=json.loads((root/'data/ctf/inventory.json').read_text(encoding='utf-8'))
    assert len(cases['positive'])>=60 and len(cases['negative'])>=12 and len(cases['multiturn'])==12
    assert {q['category'] for q in cases['positive']}==set(inv['categories'])
    assert sum(q['split']=='holdout' for q in cases['positive'])>=len(cases['positive'])//3
    paths={'ctf-wiki:'+r['path'] for r in inv['pages'] if not r['reason']}
    assert all(set(q['gold'])<=paths for q in cases['positive'])
    assert cases['annotation_status']=='draft-source-review-required'


def test_full_coverage_flag_rejects_silently_skipped_pages():
    from secrag.remote_build import verify_ctf_coverage
    report={'commit':'a'*40, 'complete':True, 'prepared':1,
            'pages':[{'path':'misc/png.md','status':'prepared','reason':''},
                     {'path':'web/sqli.md','status':'pending','reason':''}]}
    with pytest.raises(ValueError,match='未入库'):
        verify_ctf_coverage([document()],report,{'commit':'a'*40})


def test_model_call_budget_reserves_before_rpc_and_does_not_exceed_limit():
    from secrag.llm import ModelClient
    model=ModelClient.__new__(ModelClient)
    model.calls, model.max_calls=0,2
    reservations=[];model.on_call=lambda:reservations.append(model.calls)
    model._start();model._start()
    with pytest.raises(RuntimeError,match='调用上限'):
        model._start()
    assert model.calls==2 and reservations==[1,2]


def test_remote_encoding_rejects_token_truncation_before_encode(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace
    from secrag.remote_build import export_bundle
    class SmallEncoder:
        max_seq_length=4
        tokenizer=SimpleNamespace(encode=lambda text,**kwargs:list(text))
        def __init__(self,*a,**k):pass
        def encode(self,*a,**k):pytest.fail('不得静默截断后编码')
    monkeypatch.setitem(sys.modules,'sentence_transformers',SimpleNamespace(SentenceTransformer=SmallEncoder))
    (tmp_path/'docs.jsonl').write_text(json.dumps(document()),encoding='utf-8')
    write_json(tmp_path/'source-lock.json',{'commit':'a'*40})
    write_json(tmp_path/'coverage.json',{'commit':'a'*40,'prepared':1,'complete':True,
                                       'pages':[{'path':'misc/png.md','status':'prepared','reason':''}]})
    with pytest.raises(ValueError,match='token 上限'):
        export_bundle(tmp_path/'docs.jsonl',tmp_path/'bundle','test','a'*40,strategy='ctf')
    assert not (tmp_path/'bundle').exists()


def test_no_wiki_hits_can_analyze_user_code_without_fake_citation():
    e=engine(); e.retriever.retrieve=lambda *a,**k: ([], {'route':'test'})
    e.model.response='根据你贴出的代码，数组有一个元素。未找到 Wiki 支持，需进一步验证。\n```python\na[99]\n```'
    result=run(e, '```python\na = [99]\n```')
    assert result['sources']==[] and e.model.answers[-1]['wiki_evidence']==[]
    e.model.response='不存在的资料 [1]'
    with pytest.raises(RuntimeError, match='无效引用'):
        run(e, '```python\na = [99]\n```')


def test_methods_without_hits_does_not_make_up_answer():
    e=engine(); e.retriever.retrieve=lambda *a,**k: ([], {})
    e.model.transform=lambda p,q: p.update(intent='methods')
    result=run(e, '某种未知方法')
    assert '没有找到支持' in result['answer'] and not e.model.answers


def test_ctf_api_persistence_materials_replay_retry_and_profile_validation(tmp_path):
    e=engine(); app=create_app(tmp_path/'ctf.db', e); client=TestClient(app)
    assert client.get('/api/health').json()['profile']=='ctf'
    assert client.get('/api/options').json()['max_input']==16000
    sid=client.post('/api/sessions').json()['id']; url=f'/api/sessions/{sid}/messages'
    payload={'request_id':'one','question':'工具提示 IHDR CRC error','categories':['misc']}
    assert 'event: done' in client.post(url,json=payload).text
    before=len(e.model.plans)
    assert 'event: done' in client.post(url,json=payload).text and len(e.model.plans)==before
    with app.state.store.connect() as db:
        assert db.execute('SELECT text FROM materials').fetchone()[0]==payload['question']
    assert client.post(url,json={**payload,'request_id':'two','categories':['bad']}).status_code==422
    assert client.post(url,json={**payload,'request_id':'two','mode':'vulnerability'}).status_code==422
    restored=TestClient(create_app(tmp_path/'ctf.db', engine()))
    turn=restored.get('/api/sessions/'+sid).json()['turns'][0]
    assert turn['result']['sources'][0]['version']=='a'*40
    assert turn['result']['evidence_snapshot'] == e.model.answers[-1]['wiki_evidence']
    assert turn['result']['trace']['context']['selected_chunk_ids'] == [
        source['id'] for source in turn['result']['evidence_snapshot']]
    assert turn['result']['trace']['query_runs']
    assert restored.post('/api/sessions/'+sid+'/clear').status_code==200
    with app.state.store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM materials').fetchone()[0]==0


def test_pending_ctf_app_can_show_ui_without_loading_or_falling_back(tmp_path, monkeypatch):
    from secrag import library
    monkeypatch.setattr(library, 'validate_ctf_library', lambda _: (_ for _ in ()).throw(ValueError('CTF 尚未导入')))
    client=TestClient(create_app(tmp_path/'pending.db', profile='ctf'))
    options=client.get('/api/options').json()
    assert options['profile']=='ctf' and options['ready'] is False
    assert 'ctf-wiki' in options['sources']


def test_failed_ctf_stream_excludes_state_on_manual_retry(tmp_path):
    e=engine(); original=e.model.stream
    def fail(messages):
        yield '残缺'
        raise TimeoutError()
    e.model.stream=fail
    client=TestClient(create_app(tmp_path/'ctf.db', e)); sid=client.post('/api/sessions').json()['id']
    url=f'/api/sessions/{sid}/messages'
    assert 'event: error' in client.post(url,json={'request_id':'a','question':'CRC error'}).text
    e.model.stream=original
    assert 'event: done' in client.post(url,json={'request_id':'b','question':'CRC error'}).text
    assert e.model.plans[-1]['history']==[] and not e.model.plans[-1]['state']


def test_ctf_export_import_verifies_full_source_reconstruction(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace
    from secrag import config
    from secrag.remote_build import export_bundle, import_bundle
    class FakeEncoder:
        max_seq_length=8192
        tokenizer=SimpleNamespace(encode=lambda text, **kwargs: list(text))
        def __init__(self,*a,**k): pass
        def get_sentence_embedding_dimension(self): return 2
        def encode(self,texts,**kwargs): return np.ones((len(texts),2),dtype=np.float32)
    monkeypatch.setitem(sys.modules,'sentence_transformers',SimpleNamespace(SentenceTransformer=FakeEncoder))
    doc=document(); prepared=tmp_path/'prepared'; prepared.mkdir()
    (prepared/'docs.jsonl').write_text(json.dumps(doc),encoding='utf-8')
    write_json(prepared/'coverage.json',{'complete':True,'commit':'a'*40, 'prepared':1,
                                       'pages':[{'path':'misc/png.md','status':'prepared','reason':''}]})
    write_json(prepared/'source-lock.json',{'commit':'a'*40}); (prepared/'LICENSE').write_text('test')
    bundle=tmp_path/'bundle'; export_bundle(prepared/'docs.jsonl',bundle,'test','a'*40,strategy='ctf')
    m=json.loads((bundle/'index_manifest.json').read_text()); assert m['schema_version']==2 and m['complete']
    monkeypatch.setattr(config,'PROCESSED_DIR',tmp_path/'imported')
    monkeypatch.setattr(config,'CHROMA_DIR',tmp_path/'chroma')
    from secrag.store import VectorStore
    monkeypatch.setattr('secrag.store.VectorStore',lambda: VectorStore(tmp_path/'chroma'))
    import_bundle(bundle)
    from secrag.library import validate_ctf_library
    assert validate_ctf_library(tmp_path/'imported')['source_commit']=='a'*40
    (tmp_path/'imported/docs.jsonl').write_text('tamper')
    with pytest.raises(ValueError,match='校验失败'): validate_ctf_library(tmp_path/'imported')
