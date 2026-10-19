import ast
import json

import pytest

from secrag.ctf_chunker import chunk_ctf, select_ctf_context
from secrag.ctf_reliability import arithmetic_checks, evidence_corrections, literal_value, source_scopes, scope_violation
from secrag.retriever import Retriever
from tests.test_ctf import Encoder, Model, Vector, document, run
from secrag.ctf_chat import CtfChatEngine
from secrag.ctf_retrieval import retrieve_ctf


@pytest.mark.parametrize('values,key,expected', [([65,66,67],7,[70,69,68]),
    ([0,255,128],0x55,[85,170,213]), ([17,18],3,[18,17])])
def test_literal_comprehensions_checked_without_running_code(values,key,expected):
    material={'message_id':'user-1','text':f'```python\ndata={values}\nresult=[b^{key} for b in data]\n```'}
    checks=arithmetic_checks([material])
    assert checks[-1]['result']==expected
    assert checks[-1]['message_id']=='user-1' and not checks[-1]['user_code_executed']


@pytest.mark.parametrize('expr', ['__import__("os").system("echo bad")', '[0]*100000000',
    '2**100000000', '1 << 100000000', '[x for x in range(10)]', 'True+1', '1/2'])
def test_literal_interpreter_rejects_calls_allocations_and_unbounded_operations(expr):
    with pytest.raises(ValueError):
        literal_value(ast.parse(expr,mode='eval').body)


def test_entire_code_block_is_rejected_if_it_contains_executable_statements():
    assert arithmetic_checks([{'message_id':'x','text':'```python\na=1^2\nprint(a)\n```'}])==[]
    assert arithmetic_checks([{'message_id':'x','text':'```python\na=1//0\n```'}])==[]


def test_erratum_is_separate_from_original_and_identifies_source():
    source={'doc_id':'ctf-wiki:web/php/php.md','id':'php#1','number':2,
            'section':'PHP > 文件包含','text':'文件包含：readfile()，include()'}
    before=json.dumps(source)
    correction=evidence_corrections([source])[0]
    assert json.dumps(source)==before
    assert correction['evidence_number']==2 and correction['chunk_id']=='php#1'
    assert correction['authorities'] and correction['original_text_sha256']
    assert not evidence_corrections([{**source,'doc_id':'unrelated'}])


def test_abi_scope_is_extracted_and_generic_x64_claim_is_rejected():
    source={'number':1,'id':'abi#1','text':'System V AMD64 ABI (Linux、FreeBSD、macOS等采用) '
            '前六个整型参数位于 RDI, RSI, RDX, RCX, R8, R9。'}
    scope=source_scopes([source])[0]
    assert scope['scope_excerpts'][0]==source['text']
    assert scope_violation('x64 参数位于 RDI, RSI, RDX, RCX, R8, R9。',[source])
    assert not scope_violation('System V AMD64 ABI 的整型参数使用 RDI 到 R9。',[source])
    assert not scope_violation('调用约定应从目标程序确认。',[source])


@pytest.mark.parametrize('doc,section,text,erratum', [
    ('crypto/asymmetric/rsa/rsa_e_attack.md', '小公钥指数攻击 > 攻击原理', 'm^3=c+kN', 'rsa-value-vs-encoded-length-scope-v1'),
    ('web/sqli.md', '基本概念', 'SQL 将输入参数传给数据库。', 'sql-input-binding-scope-v1'),
    ('misc/traffic/fix.md', '常见块 > Interface Description Block', 'Interface Description Block 定义接口。', 'pcapng-block-format-scope-v1'),
    ('pwn/linux/user-mode/summary/get-address.md', '`pwnlib.dynelf`', '高地址环境变量被覆盖。', 'dynelf-read-side-effects-v1'),
    ('pwn/linux/user-mode/heap/ptmalloc2/tcache-attack.md', 'tcache dup', 'tcache_put 重复释放示例。', 'tcache-historical-example-scope-v1'),
    ('pwn/linux/user-mode/stackoverflow/x86/stack-intro.md', '函数调用栈', 'x86 与 x64 栈示意。', 'stack-example-abi-scope-v1'),
    ('misc/picture/png.md', '隐写软件', '[Stepic](https://example.invalid/)', 'png-stepic-evidence-limit-v1'),
    ('misc/archive/zip.md', '明文攻击 > 例题', 'pkcrack 已知明文例题。', 'zip-known-plaintext-cipher-scope-v1'),
    ('web/php/php.md', '直接执行代码', 'eval(); assert(); system(); escapeshellcmd();', 'php-execution-sinks-scope-v1'),
    ('web/php/php.md', 'Curly Syntax', '花括号的 foobar 示例。', 'php-interpolation-source-scope-v1'),
    ('crypto/asymmetric/rsa/rsa_coppersmith_attack.md', 'Coppersmith’s short-pad attack > 攻击原理', 'padding bound floor(k/e^2)', 'rsa-short-pad-bound-scope-v1'),
    ('crypto/asymmetric/rsa/rsa_theory.md', '2018 CodeGate CTF Rsababy', 'g=d*(p-0xdeadbeef), gcd 求解。', 'rsa-leak-relation-scope-v1'),
    ('web/php/php.md', '内置函数的参数的松散性', 'md5(array) 与 strcmp(array)；in_array 非严格比较。', 'php-comparison-version-v1'),
    ('crypto/asymmetric/rsa/rsa_theory.md', '消息加密', '将消息转成与 N 互质的整数。', 'rsa-message-coprimality-v1'),
    ('misc/picture/png.md', 'IHDR', '数据由13字节组成，其中关注前8字节。', 'png-ihdr-data-scope-v1'),
    ('pwn/linux/user-mode/stackoverflow/x86/stack-intro.md', '函数调用栈', '内存地址不能大于 0x00007FFFFFFFFFFF。', 'x64-address-scope-v1'),
    ('web/sqli.md', '注入常见参数', 'concat() 联合字符串；group_concat() 收集多条数据。', 'mysql-concat-aggregation-scope-v1'),
    ('executable/elf/structure/basic-info.md', 'Program Header Table > 概述', '条目数组 Elf32_Phdr。', 'elf-program-header-class-v1'),
    ('misc/traffic/protocols/wireshark.md', 'Protocol History(协议分级)', 'Protocol History 窗口展示协议统计。', 'wireshark-protocol-hierarchy-name-v1'),
    ('misc/archive/zip.md', '明文攻击 > 原理', '需要12字节明文。', 'zip-known-plaintext-cipher-scope-v1'),
])
def test_source_conflict_reaches_both_draft_and_final_review_without_mutation(doc,section,text,erratum):
    d=document(doc, '# 示例\n## '+section+'\n'+text)
    cs=chunk_ctf(d)
    originals=json.dumps(cs,ensure_ascii=False,sort_keys=True)
    model=Model()
    result=run(CtfChatEngine(Retriever(cs,Vector(cs),Encoder()),model),'请解释这个方法的条件和范围')
    for payload in [model.drafts[-1],model.answers[-1]]:
        correction=next(c for c in payload['evidence_corrections'] if c['id']==erratum)
        source=next(s for s in payload['wiki_evidence'] if s['number']==correction['evidence_number'])
        assert text in source['text']
        import hashlib
        assert correction['original_text_sha256']==hashlib.sha256(source['text'].encode()).hexdigest()
    assert result['trace']['evidence_corrections']
    assert json.dumps(cs,ensure_ascii=False,sort_keys=True)==originals


def test_rsa_coprimality_erratum_has_valid_counterexamples():
    # Independent modular round-trips disprove a mandatory coprimality condition.
    from math import gcd
    for p,q,e,d in [(5,11,3,27),(7,11,7,43)]:
        n=p*q
        assert e*d%((p-1)*(q-1))==1
        for m in [0,p,q,2*p,n-1]:
            assert pow(pow(m,e,n),d,n)==m
        assert gcd(p,n)>1


def test_exact_subject_survives_top_five_and_trace_explains_truncation():
    docs=[document(f'misc/generic{i}.md',f'# 通用{i}\n检查图片隐写内容。') for i in range(6)]
    for i,d in enumerate(docs):d['title']=f'通用{i}'
    png=document('misc/png.md','# PNG\nPNG 隐写 LSB 方法。');png['title']='PNG'
    cs=[c for d in docs+[png] for c in chunk_ctf(d)]
    r=Retriever(cs,Vector(cs),Encoder())
    r.search_bm25=lambda q,k:[]
    hits,trace=r.retrieve('PNG 隐写方法',top_k=5)
    assert hits[0]['doc_id']==png['id']
    assert trace['fusion_document_order'].index(png['id'])==6
    assert trace['selected_document_ids'][0]==png['id']
    assert len(trace['truncated_document_ids'])==2
    assert trace['queries'][0]['vector'] and trace['queries'][0]['query']=='PNG 隐写方法'
    assert r.scoped(categories=['web']) is None


def test_definition_and_method_principles_are_selected_as_a_bundle():
    d=document('crypto/example.md','# 示例\n## 基本原理\n### 密钥的产生\n定义参数。\n'
               '### 消息加密\n密文等于模幂。\n### 消息解密\n逆变换。\n'
               '## 小指数\n### 攻击条件\n小指数。\n### 攻击原理\n密文加模数的倍数再开根。', ['crypto'])
    cs=chunk_ctf(d);r=Retriever(cs,Vector(cs),Encoder())
    decrypt=next(c for c in cs if c['section'].endswith('消息解密'))
    hits,trace=select_ctf_context('基本参数和加解密关系是什么',[r._hit(decrypt['id'],1)],r)
    assert any(h['section'].endswith('消息加密') for h in hits)
    assert any(h['section'].endswith('密钥的产生') for h in hits)
    condition=next(c for c in cs if c['section'].endswith('攻击条件'))
    hits,trace=select_ctf_context('小指数怎么分析',[r._hit(condition['id'],1)],r)
    assert any(h['section'].endswith('攻击原理') for h in hits)
    assert trace['selection_reasons'] and trace['strategy']=='ctf-context-v3'
    assert all(len(h['text'])<=16000 for h in hits)


def test_later_document_example_cannot_escape_its_own_method_conditions():
    cs=chunk_ctf(document('misc/other.md','# 其他\n## 概述\n无关背景。'))
    cs+=chunk_ctf(document('misc/archive/demo.md','# 格式\n## 明文攻击\n### 原理\n仅用于传统流加密。\n### 例题\n运行破解工具。'))
    r=Retriever(cs,Vector(cs),Encoder())
    first=next(c for c in cs if c['doc_id'].endswith('other.md') and '无关' in c['text'])
    example=next(c for c in cs if c['section'].endswith('例题'))
    recalled=[r._hit(first['id'],1),r._hit(example['id'],1)]
    hits,_=select_ctf_context('文件一般怎么分析',recalled,r)
    assert any(h['id']==example['id'] for h in hits)
    assert any('仅用于传统流加密' in h['text'] for h in hits)
    hits,_=select_ctf_context('文件一般怎么分析',recalled,r,max_chunks=2)
    assert not any(h['id']==example['id'] for h in hits)


def test_followup_keeps_multiple_explicit_methods_without_broad_query_word():
    cs=chunk_ctf(document('misc/picture/png.md','# PNG\n## 文件格式\nPNG由块组成。\n### IHDR\n宽高字段。\n## LSB\n像素最低位可用Stegsolve观察。'))
    r=Retriever(cs,Vector(cs),Encoder())
    ihdr=next(c for c in cs if c['section'].endswith('IHDR'))
    hits,trace=select_ctf_context('尾部没有额外数据；接着检查像素LSB与IHDR宽高字段',
                                [r._hit(ihdr['id'],1)],r)
    assert any(h['section'].endswith('IHDR') for h in hits)
    assert any(h['section'].endswith('LSB') for h in hits)
    assert 'explicit_method_group' in trace['selection_reasons'].values()


def test_generic_flag_expansion_cannot_outvote_actual_chinese_subject():
    intro=document('reverse/introduction.md','# 软件逆向工程简介\n## 常规逆向流程\n逆向分析的基本流程。')
    intro['title']='软件逆向工程简介'
    android=document('android/demo.md','# 静态分析原生层程序\n## 获取flag\n一个安卓例子。')
    android['title']='静态分析原生层程序'
    cs=chunk_ctf(intro)+chunk_ctf(android)
    r=Retriever(cs,Vector(cs),Encoder())
    hits,_=r.retrieve('CTF逆向题开始分析的通用方法和输出flag流程',10)
    assert hits[0]['doc_id'].endswith('reverse/introduction.md')


def test_summary_preserves_negative_user_result_without_generation():
    cs=chunk_ctf(document());model=Model();e=CtfChatEngine(Retriever(cs,Vector(cs),Encoder()),model)
    original='我检查了文件尾，没有附加数据；LSB 还没有检查。'
    first=run(e,original)
    first['state']['attempts']=[{'text':'我检查了文件尾，没有附加数据','message_id':first['message_id']}]
    history=[{'id':first['message_id'],'question':original,'answer':first['answer'],'result':first,'status':'complete'}]
    calls=len(model.plans),len(model.drafts),len(model.answers)
    result=run(e,'总结已尝试的方法',history,quick='summary')
    assert (len(model.plans),len(model.drafts),len(model.answers))==calls
    assert original in result['answer'] and '我检查了文件尾，没有附加数据' in result['answer']
    assert '未给出结果' not in result['answer']
    assert result['state']==first['state'] and result['sources']==[]
    assert result['trace']['generation_strategy']=='validated_user_quotes_summary_v1'


def test_full_evidence_snapshot_includes_uncited_chunks_and_arithmetic_provenance():
    cs=chunk_ctf(document());model=Model();e=CtfChatEngine(Retriever(cs,Vector(cs),Encoder()),model)
    result=run(e,'```python\na=[0x10,0x11]\nb=[x^3 for x in a]\n```')
    assert result['trace']['arithmetic_checks'][-1]['result']==[19,18]
    assert result['evidence_snapshot']==model.answers[-1]['wiki_evidence']
    assert result['trace']['cited_numbers']==[1]
    assert result['trace']['effective_query']==result['query']
    assert model.answers[-1]['answer_draft'] == model.response
    assert model.drafts[-1]['wiki_evidence'] == model.answers[-1]['wiki_evidence']
    assert result['trace']['generation_strategy']=='draft_then_grounded_stream_v1'


def test_draft_is_not_streamed_or_persisted_as_final_answer_on_review_failure():
    cs=chunk_ctf(document());model=Model();e=CtfChatEngine(Retriever(cs,Vector(cs),Encoder()),model)
    def fail(messages):
        assert 'answer_draft' in json.loads(messages[-1]['content'])
        raise TimeoutError('review interrupted')
        yield
    model.stream=fail
    emitted=[]
    with pytest.raises(TimeoutError):
        for kind,data in e.events('PNG IHDR',[],{'mode':'auto'}):
            emitted.append(kind)
    assert 'done' not in emitted and 'delta' not in emitted
    assert model.drafts


def test_two_query_fusion_preserves_original_and_quick_reference_skips_raw():
    class Scope:
        def __init__(self):self.queries=[]
        def retrieve(self,q,k):
            self.queries.append(q)
            ids=['right','shared','wrong'] if q=='PNG 隐写方法' else ['wrong','shared','right']
            return [{'doc_id':key,'id':key+'#0'} for key in ids], {'query':q}
    scope=Scope()
    hits,trace=retrieve_ctf(scope,'PNG 隐写方法','扩写主题',top_k=1)
    assert hits[0]['doc_id']=='right' and trace['original_query_used']
    assert len(trace['query_runs'])==2 and len(trace['truncated_document_ids'])==2
    scope=Scope()
    _,trace=retrieve_ctf(scope,'第二点 PNG 怎么做','PNG具体方法',quick='next')
    assert scope.queries==['PNG具体方法'] and not trace['original_query_used']


def test_named_chinese_reference_survives_planner_attack_list_expansion():
    raw='你刚才的小指数假设还能成立吗？'
    effective='RSA oracle 多组密文和各种其他路线'
    class Scope:
        def retrieve(self,q,k):
            ids=['small','oracle'] if q==raw else ['oracle','small']
            titles={'small':'公钥指数相关攻击','oracle':'RSA 选择明密文攻击'}
            return [dict(doc_id=i,id=i+'#0',title=titles[i]) for i in ids], {'query':q}
    hits,trace=retrieve_ctf(Scope(),raw,effective,top_k=1)
    assert trace['original_query_used'] and hits[0]['doc_id']=='small'
    _,trace=retrieve_ctf(Scope(),'你刚才那个假设还能成立吗？',effective,top_k=1)
    assert not trace['original_query_used']
    _,trace=retrieve_ctf(Scope(),'第二点是什么意思？',effective,top_k=1)
    assert not trace['original_query_used'] and len(trace['query_runs'])==1


def test_broad_trailing_word_is_not_the_named_chinese_subject():
    raw='异或编码一般怎么理解？'
    effective='XOR运算的原理和性质'
    class Scope:
        def retrieve(self,q,k):
            row=dict(doc_id='encoding',id='encoding#0',title='计算机相关的编码') if q==raw else dict(
                doc_id='xor',id='xor#0',title='ARX加密')
            return [row], {'query':q}
    hits,trace=retrieve_ctf(Scope(),raw,effective)
    assert not trace['original_query_used'] and hits[0]['doc_id']=='xor'


def test_single_character_stack_subject_and_role_question_prioritize_foundation():
    smali=document('android/smali.md','# Smali\n## 方法调用\n函数调用通过指令传递参数和返回结果。')
    smali['title']='Smali'
    stack=document('pwn/stack-intro.md','# 栈介绍\n## 函数调用栈\n栈在函数调用时保存返回地址和局部数据。')
    stack['title']='栈介绍'
    cs=chunk_ctf(smali)+chunk_ctf(stack)
    r=Retriever(cs,Vector(cs),Encoder())
    hits,_=r.retrieve('栈在函数调用中起什么作用？',10)
    assert hits[0]['doc_id'].endswith('stack-intro.md')
    hits,trace=retrieve_ctf(r,'栈在函数调用中起什么作用？','函数调用时的各种方法、指令和执行机制')
    assert trace['original_query_used'] and hits[0]['doc_id'].endswith('stack-intro.md')


def test_encoded_byte_upper_bound_is_not_necessary_for_unwrapped_root():
    for encoded,n,e in [(b'\x01',55,3),(b'\x00\x05',391,3)]:
        m=int.from_bytes(encoded,'big')
        assert m**e < n
        assert 256**(e*len(encoded)) >= n


def test_example_gets_parent_and_binary_field_definitions():
    d=document('misc/format.md','# 格式\n## 字段\n| 名称 | 字节数 |\n| CRC | 4 |\n'
               '### IHDR\n数据区13字节。\n#### 例题\n宽高可改。')
    cs=chunk_ctf(d);r=Retriever(cs,Vector(cs),Encoder())
    anchor=next(c for c in cs if c['section'].endswith('例题'))
    hits,_=select_ctf_context('IHDR CRC 字段长度',[r._hit(anchor['id'],1)],r)
    assert any('数据区13字节' in h['text'] for h in hits)
    assert any('| CRC | 4 |' in h['text'] for h in hits)


def test_code_recalled_in_middle_recovers_whole_sequence_or_omits_it():
    d=document('misc/long_code.md','# 示例\n## 算法\n```python\n'+
               ''.join(f'value_{i} = {i}\n' for i in range(100))+'```\n')
    cs=chunk_ctf(d,max_chars=180)
    chain=[c for c in cs if c['meta'].get('continued_code') or c['meta'].get('continues_code')]
    assert len(chain)>3
    r=Retriever(cs,Vector(cs),Encoder())
    middle=r._hit(chain[len(chain)//2]['id'],1)
    hits,trace=select_ctf_context('代码',[middle],r,max_chars=10000,max_chunks=100)
    ids={h['id'] for h in hits}
    assert {h['id'] for h in chain}<=ids
    small,trace=select_ctf_context('代码',[middle],r,max_chars=100,max_chunks=1)
    assert not small and trace['omitted_chunks']>0
    assert set(trace['skip_reasons'].values())=={'whole_evidence_budget'}


def test_code_continuation_cannot_recover_missing_scope_fragments():
    d=document('misc/long_code.md','# 示例\n```python\n'+
               ''.join(f'x_{i} = {i}\n' for i in range(60))+'```\n')
    cs=chunk_ctf(d,max_chars=180)
    middle=next(c for c in cs if c['meta']['continued_code'] and c['meta']['continues_code'])
    r=Retriever([middle],Vector([middle]),Encoder())
    hits,trace=select_ctf_context('代码',[r._hit(middle['id'],1)],r)
    assert hits==[] and trace['skip_reasons'][middle['id']]=='incomplete_code_chain'
