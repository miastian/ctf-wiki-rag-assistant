"""本地会话存储，每个请求只有一个事务化的运行记录。"""
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


class BusyError(Exception):
    pass


@contextmanager
def process_lock(path):
    """锁由操作系统在进程退出时释放，避免第二个服务错误恢复正在执行的请求。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise BusyError("已有应用进程使用该会话数据库，请复用已启动的应用") from exc
        yield


class ChatStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS turns (
                    id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    request_id TEXT NOT NULL, question TEXT NOT NULL, settings TEXT NOT NULL,
                    status TEXT NOT NULL, answer TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '{}',
                    created REAL NOT NULL, UNIQUE(session_id, request_id));
                CREATE UNIQUE INDEX IF NOT EXISTS one_running_per_session ON turns(session_id)
                    WHERE status='running';
                CREATE TABLE IF NOT EXISTS materials (
                    turn_id TEXT PRIMARY KEY REFERENCES turns(id) ON DELETE CASCADE,
                    text TEXT NOT NULL);
            """)
            # 单进程本地应用启动时恢复上次崩溃留下的请求。
            db.execute("UPDATE turns SET status='interrupted' WHERE status='running'")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self):
        sid, now = str(uuid.uuid4()), time.time()
        with self.connect() as db:
            db.execute("INSERT INTO sessions VALUES(?,?,?,?)", (sid, "新会话", now, now))
        return self.get(sid)

    def list(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM sessions ORDER BY updated DESC")]

    def get(self, sid):
        with self.connect() as db:
            row = db.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
            if row is None:
                raise KeyError(sid)
            turns = [self.decode(r) for r in db.execute(
                "SELECT * FROM turns WHERE session_id=? ORDER BY created,rowid", (sid,))]
            return {**dict(row), "turns": turns}

    @staticmethod
    def decode(row):
        return {**dict(row), "settings": json.loads(row["settings"]), "result": json.loads(row["result"])}

    def reserve(self, sid, request_id, question, settings):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM sessions WHERE id=?", (sid,)).fetchone():
                raise KeyError(sid)
            row = db.execute("SELECT * FROM turns WHERE session_id=? AND request_id=?", (sid, request_id)).fetchone()
            if row:
                turn = self.decode(row)
                if turn["question"] != question or turn["settings"] != settings:
                    raise ValueError("同一请求编号不能对应不同内容")
                if turn["status"] == "running":
                    raise BusyError("该请求正在执行")
                return turn, False
            if db.execute("SELECT 1 FROM turns WHERE session_id=? AND status='running'", (sid,)).fetchone():
                raise BusyError("当前会话有正在执行的请求")
            tid, now = str(uuid.uuid4()), time.time()
            db.execute("INSERT INTO turns(id,session_id,request_id,question,settings,status,created) VALUES(?,?,?,?,?,'running',?)",
                       (tid, sid, request_id, question, json.dumps(settings), now))
            if settings.get('profile') == 'ctf':
                db.execute('INSERT INTO materials(turn_id,text) VALUES(?,?)', (tid, question))
            db.execute("UPDATE sessions SET title=CASE WHEN title='新会话' THEN ? ELSE title END,updated=? WHERE id=?",
                       (question[:28], now, sid))
            return self.decode(db.execute("SELECT * FROM turns WHERE id=?", (tid,)).fetchone()), True

    def finish(self, tid, status, answer, result):
        with self.connect() as db:
            db.execute("UPDATE turns SET status=?,answer=?,result=? WHERE id=? AND status='running'",
                       (status, answer, json.dumps(result, ensure_ascii=False), tid))

    def remove(self, sid, clear=False):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM sessions WHERE id=?", (sid,)).fetchone():
                raise KeyError(sid)
            if db.execute("SELECT 1 FROM turns WHERE session_id=? AND status='running'", (sid,)).fetchone():
                raise BusyError("请等待当前回答结束")
            db.execute("DELETE FROM turns WHERE session_id=?", (sid,))
            if clear:
                db.execute("UPDATE sessions SET title='新会话',updated=? WHERE id=?", (time.time(), sid))
            else:
                db.execute("DELETE FROM sessions WHERE id=?", (sid,))
