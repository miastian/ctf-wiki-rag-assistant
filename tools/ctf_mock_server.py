"""Synthetic browser-test server; never launched by the product entry point."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if __name__ == '__main__':
    import uvicorn
    from tests.test_ctf import engine
    from secrag.web import create_app
    e = engine()
    original = e.model.stream
    failed = set()
    def stream(messages):
        import json
        question = json.loads(messages[-1]['content'])['question']
        if '模拟失败' in question and question not in failed:
            failed.add(question)
            yield '未完成'
            raise TimeoutError()
        yield from original(messages)
    e.model.stream = stream
    app = create_app(ROOT/'artifacts/ctf-browser.sqlite3', e)
    uvicorn.run(app, host='127.0.0.1', port=8767)
