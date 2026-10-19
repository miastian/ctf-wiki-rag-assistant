"""CTF evaluation: list cases by default; --retrieval or --live requires a real imported CTF library."""
import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group()
    group.add_argument('--retrieval', action='store_true'); group.add_argument('--live', action='store_true')
    p.add_argument('--out'); p.add_argument('--max-calls', type=int, default=100)
    p.add_argument('--resume-from', help='复用旧报告已完成前缀，累计调用仍受同一个上限约束')
    p.add_argument('--rerun', nargs='*', default=[], help='显式重测指定案例，其余完成前缀复用')
    p.add_argument('--rerun-from-turn', nargs='*', default=[], metavar='CASE:TURN', help='保留该案例前缀，从指定轮次起重测后续轮次')
    args = p.parse_args()
    if not 1 <= args.max_calls <= 100:
        p.error('max-calls 必须为1..100')
    path = ROOT/'data/eval/ctf_cases.json'
    cases = json.loads(path.read_text(encoding='utf-8'))
    if not args.live and not args.retrieval:
        print(json.dumps({'positives':len(cases['positive']), 'negatives':len(cases['negative']),
                          'multiturn_groups':len(cases['multiturn']), 'annotation_status':cases['annotation_status'],
                          'paid_calls':0}, ensure_ascii=False))
        return
    if not args.out:
        p.error('执行验收需指定全新的 --out 文件')
    output = Path(args.out)
    if output.exists():
        p.error('禁止覆盖旧结果')
    os.environ['SECRAG_PROFILE'] = 'ctf'
    os.environ.setdefault('SECRAG_EXPERIMENT', 'ctf_wiki_v1')
    os.environ.setdefault('EMBED_MODEL', 'BAAI/bge-m3')
    from secrag.cli import make_retriever
    retriever = make_retriever(use_reranker=False)
    report = {'case_sha256':hashlib.sha256(path.read_bytes()).hexdigest(), 'source_commit':cases['source_commit'],
              'annotation_status':cases['annotation_status'], 'candidate_passed':False, 'records':[],
              'manual_review':'pending', 'max_calls':args.max_calls, 'automatic_retries':0}
    report['code_sha256'] = {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
                             for name in ('secrag/ctf_chat.py','secrag/ctf_chunker.py','secrag/llm.py')}
    old = json.loads(Path(args.resume_from).read_text(encoding='utf-8')) if args.resume_from else {}
    if old and (old['case_sha256'] != report['case_sha256'] or old['source_commit'] != report['source_commit']):
        raise ValueError('旧报告与冻结场景或资料版本不一致，不能复用')
    base_calls = old.get('aggregate_calls', old.get('calls', 0))
    report['resume_parent'] = args.resume_from
    from secrag.config import PROCESSED_DIR
    manifest = json.loads((PROCESSED_DIR/'index_manifest.json').read_text(encoding='utf-8'))
    if manifest['source_commit'] != cases['source_commit']:
        raise ValueError('评测资料版本与索引不一致')
    def save():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    if args.retrieval:
        for case in cases['positive'] + cases['negative']:
            hits, trace = retriever.retrieve(case['question'], top_k=10)
            report['records'].append({'id':case['id'], 'documents':[h['doc_id'] for h in hits], 'trace':trace,
                                      'gold':case.get('gold', []), 'split':case.get('split', 'negative')})
        for split in ('dev','holdout'):
            rows = [r for r in report['records'] if r['split']==split]
            report[split] = {'questions':len(rows), 'any_gold_R@10':sum(bool(set(r['gold']) & set(r['documents'])) for r in rows)/len(rows)}
        save(); return
    from secrag.ctf_chat import CtfChatEngine
    from secrag.llm import ModelClient
    if base_calls > args.max_calls:
        raise ValueError('累计模型调用已到上限')
    model = ModelClient(timeout=180, max_calls=args.max_calls-base_calls)
    model.on_call = lambda: (report.update(calls=model.calls, aggregate_calls=base_calls+model.calls,
                                          usage=model.usage, usage_unknown_calls=max(0, model.calls-len(model.usage))), save())
    engine = CtfChatEngine(retriever, model, manifest)
    # Six representative positive singles + six negatives + twelve 3-turn groups.
    singles = []
    for category in ('web','misc','reverse','crypto','pwn','executable'):
        singles.append(next(c for c in cases['positive'] if c['category']==category))
    negatives=[c for c in cases['negative'] if c['id'] in ('n01','n03','n05','n06','n13','n16')]
    selected = [{'id':c['id'], 'turns':[c['question']], 'expected':c.get('expected','human review')} for c in singles+negatives] + cases['multiturn']
    report['expected_turns'] = sum(len(c['turns']) for c in selected)
    report['calls'], report['usage'] = 0, []
    rerun_turns = {}
    for item in args.rerun_from_turn:
        key, number = item.rsplit(':', 1)
        if not number.isdigit() or int(number) < 1:
            p.error('rerun-from-turn 格式必须为 CASE:正整数')
        rerun_turns[key] = min(int(number), rerun_turns.get(key, int(number)))
    completed = {(r['case'], r['turn']):r for r in old.get('records', [])
                 if r['status']=='complete' and r['case'] not in args.rerun
                 and r['turn'] < rerun_turns.get(r['case'], float('inf'))}
    for case in selected:
        history=[]
        for index, question in enumerate(case['turns']):
            previous = completed.get((case['id'],index+1))
            if previous:
                if previous['question']!=question:
                    raise ValueError('旧报告问题不一致')
                report['records'].append({**previous,'resumed':True, 'code_sha256':previous.get('code_sha256',old.get('code_sha256',{}))})
                data=previous['result']
                history.append({'id':data['message_id'],'question':question,'answer':data['answer'],'status':'complete','result':data})
                continue
            started=time.perf_counter()
            record={'case':case['id'], 'turn':index+1, 'question':question, 'status':'failed','code_sha256':report['code_sha256']}
            try:
                quick={'展开详细步骤':'steps','为什么这样查':'why','下一步怎么做':'next','总结已尝试的方法':'summary'}.get(question)
                for kind, data in engine.events(question, history, {'mode':'auto','quick':quick}):
                    if kind == 'done':
                        record.update(status='complete', result=data)
                        history.append({'id':data['message_id'], 'question':question, 'answer':data['answer'], 'status':'complete', 'result':data})
            except Exception as exc:
                record['error_type']=type(exc).__name__
                if type(exc) is RuntimeError:
                    record['error']=str(exc)[:300]
            finally:
                record['seconds']=round(time.perf_counter()-started,3)
                report['records'].append(record)
                report.update(calls=model.calls, aggregate_calls=base_calls+model.calls, usage=model.usage, usage_unknown_calls=max(0,model.calls-len(model.usage)))
                save()
            if record['status']!='complete':
                report['incomplete_reason']='遇到失败，停止调用；修复后用新输出文件显式继续，不自动重试'
                report['incomplete_turns']=report['expected_turns']-sum(r['status']=='complete' for r in report['records'])
                save();return
    report['incomplete_turns']=report['expected_turns']-sum(r['status']=='complete' for r in report['records'])
    save()


if __name__ == '__main__':
    main()
