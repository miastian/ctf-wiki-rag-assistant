"""CTF Wiki 多轮思路助手的本地网页/API 入口。"""
import argparse
import asyncio
import json
import os
import queue
import threading
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from secrag.chat_store import ChatStore, BusyError


class MessageRequest(BaseModel):
    request_id: str = Field(min_length=1, max_length=100)
    question: str = Field(min_length=1, max_length=16000)
    mode: Literal["auto", "explain", "vulnerability", "defense", "checklist", "methods", "next"] = "auto"
    sources: list[str] = Field(default_factory=list, max_length=20)
    language: str | None = Field(default=None, max_length=30)
    categories: list[str] = Field(default_factory=list, max_length=30)
    quick: Literal["detail", "checklist", "defense", "why", "next", "steps", "summary"] | None = None

    @field_validator("question")
    @classmethod
    def nonempty(cls, value):
        if not value.strip():
            raise ValueError("问题不能为空")
        return value.strip()


def sse(kind, data):
    return f"event: {kind}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def public_error(exc):
    """显示可操作的原因，不暴露 SDK 异常中的地址、请求或认证信息。"""
    return {
        "APIConnectionError": "无法连接回答服务，请检查服务端网络或代理设置后重试。",
        "APITimeoutError": "回答服务响应超时，可稍后重试。",
        "TimeoutError": "回答服务响应超时，可稍后重试。",
        "AuthenticationError": "回答服务认证失败，请检查本机模型配置。",
        "PermissionDeniedError": "回答服务拒绝访问，请检查模型权限。",
        "RateLimitError": "回答服务请求受限，请稍后重试。",
    }.get(type(exc).__name__, "本轮未完成，可手动重试。")


def create_app(db_path=None, engine=None, profile=None):
    root = Path(__file__).resolve().parent.parent
    if profile not in (None, 'ctf') or getattr(engine, 'profile', 'ctf') != 'ctf':
        raise ValueError('当前仅支持 CTF profile')
    profile = 'ctf'
    store = ChatStore(db_path or root / 'data/local' / 'chat-ctf.sqlite3')
    app = FastAPI(title="CTF 思路助手")
    app.state.store = store
    app.state.engine = engine
    init_lock = threading.Lock()
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])
    app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
                       allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type"])

    @app.middleware("http")
    async def same_origin(request, call_next):
        if request.method in ("POST", "DELETE"):
            origin = request.headers.get("origin")
            allowed = {str(request.base_url).rstrip("/"), "http://127.0.0.1:5173", "http://localhost:5173"}
            if origin and origin not in allowed:
                from fastapi.responses import JSONResponse
                return JSONResponse({"detail": "仅接受本机应用请求"}, status_code=403)
        return await call_next(request)

    def get_engine():
        if app.state.engine is None:
            with init_lock:
                if app.state.engine is None:
                    from secrag.cli import make_retriever
                    from secrag.llm import ModelClient
                    from secrag.config import PROCESSED_DIR
                    from secrag.library import validate_ctf_library
                    from secrag.ctf_chat import CtfChatEngine
                    manifest = validate_ctf_library(PROCESSED_DIR)
                    app.state.engine = CtfChatEngine(make_retriever(), ModelClient(), manifest)
        return app.state.engine

    @app.exception_handler(KeyError)
    async def missing(request, exc):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "会话不存在"}, status_code=404)

    @app.exception_handler(BusyError)
    async def busy(request, exc):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.get("/api/health")
    def health():
        return {"status": "ok", 'profile': profile}

    @app.get("/api/options")
    def options():
        try:
            return get_engine().options()
        except Exception as exc:
            from secrag.library import pending_options
            reason = str(exc) if isinstance(exc, ValueError) else 'CTF 知识库或模型尚未就绪，请检查导入与本机配置。'
            return pending_options(root, reason)

    @app.get("/api/sessions")
    def sessions():
        return store.list()

    @app.post("/api/sessions", status_code=201)
    def create_session():
        return store.create()

    @app.get("/api/sessions/{sid}")
    def session(sid: str):
        return store.get(sid)

    @app.delete("/api/sessions/{sid}")
    def delete_session(sid: str):
        store.remove(sid)
        return {"ok": True}

    @app.post("/api/sessions/{sid}/clear")
    def clear_session(sid: str):
        store.remove(sid, clear=True)
        return store.get(sid)

    @app.post("/api/sessions/{sid}/messages")
    def message(sid: str, body: MessageRequest):
        current = store.get(sid)
        try:
            active_engine = get_engine()
        except Exception:
            raise HTTPException(503, "无法加载知识库或模型配置") from None
        options = active_engine.options()
        if body.mode not in options['modes']:
            raise HTTPException(422, '回答形式或方向不适用于当前知识库')
        if set(body.categories) - set(options.get('categories', [])):
            raise HTTPException(422, '方向不在当前知识库中')
        if set(body.sources) - set(options["sources"]) or (body.language and body.language not in options["languages"]):
            raise HTTPException(422, "筛选项不在当前知识库中")
        settings = body.model_dump(exclude={"question", "request_id"})
        settings['profile'] = 'ctf'
        try:
            turn, fresh = store.reserve(sid, body.request_id, body.question, settings)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        if not fresh:
            async def replay():
                yield sse("done" if turn["status"] == "complete" else "error",
                          {**turn["result"], "answer": turn["answer"], "turn_id": turn["id"], "status": turn["status"]})
            return StreamingResponse(replay(), media_type="text/event-stream")
        current = store.get(sid)
        events = queue.Queue()
        stopped = threading.Event()

        def work():
            answer, result, status = "", {}, "interrupted"
            iterator = None
            try:
                iterator = active_engine.events(body.question, current["turns"], settings)
                for kind, data in iterator:
                    if stopped.is_set():
                        return
                    if kind == "delta":
                        answer += data["text"]
                    if kind == "done":
                        result, answer, status = data, data["answer"], "complete"
                        store.finish(turn["id"], status, answer, result)
                    events.put((kind, {**data, "turn_id": turn["id"]}))
                if status != "complete":
                    raise RuntimeError("回答未正常结束")
            except Exception as exc:
                status = "interrupted" if stopped.is_set() else "failed"
                result = {"error": public_error(exc), "error_type": type(exc).__name__}
                events.put(("error", {**result, "turn_id": turn["id"], "status": status}))
            finally:
                if iterator is not None:
                    try:
                        iterator.close()
                    except Exception:
                        pass
                try:
                    if status != "complete":
                        store.finish(turn["id"], status, answer, result)
                except Exception:
                    events.put(("error", {"error": "会话保存失败，请检查本机存储后重启应用。", "turn_id": turn["id"]}))
                finally:
                    events.put(None)

        async def response():
            worker = threading.Thread(target=work, daemon=True)
            worker.start()
            try:
                yield sse("start", {"turn_id": turn["id"]})
                while True:
                    try:
                        item = await asyncio.to_thread(events.get, True, 1)
                    except queue.Empty:
                        yield ": heartbeat\n\n"
                        continue
                    if item is None:
                        break
                    yield sse(*item)
            finally:
                stopped.set()
        return StreamingResponse(response(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    dist = root / "web" / "dist"
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=dist, html=True), name="web")
    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    os.environ.setdefault('SECRAG_EXPERIMENT', 'ctf_wiki_v1')
    os.environ.setdefault('EMBED_MODEL', 'BAAI/bge-m3')
    import uvicorn
    from secrag.chat_store import process_lock
    root = Path(__file__).resolve().parent.parent
    try:
        with process_lock(root / 'data/local' / 'web-ctf.lock'):
            uvicorn.run(create_app(), host="127.0.0.1", port=args.port, workers=1)
    except BusyError as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
