"""
Ватман: сервер аккаунтов и общих досок.

Отдаёт только JSON-API; сам сайт лежит статикой на GitHub Pages и обращается
сюда запросами. Хранилище — SQLite на постоянном диске Railway.

Переменные окружения:
  VATMAN_DB       путь к файлу базы            (по умолчанию ./vatman.db)
  VATMAN_ORIGINS  откуда пускать, через запятую (по умолчанию localhost для разработки)
  PORT            порт, его подставляет Railway (по умолчанию 8000)
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("VATMAN_DB", "vatman.db")
ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "VATMAN_ORIGINS",
        "http://localhost:8765,http://127.0.0.1:8765",
    ).split(",")
    if o.strip()
]

# Код приглашения: без похожих друг на друга символов, чтобы его можно было
# продиктовать голосом и не перепутать ноль с буквой O.
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LEN = 8
SESSION_DAYS = 90
SCRYPT_N = 2 ** 14

app = FastAPI(title="Ватман", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ───────────────────────────── база ─────────────────────────────

_db_lock = threading.Lock()
_db = sqlite3.connect(DB_PATH, check_same_thread=False)
_db.row_factory = sqlite3.Row
_db.execute("pragma journal_mode = wal")
_db.execute("pragma foreign_keys = on")
_db.execute("pragma busy_timeout = 5000")


@contextmanager
def tx():
    """Одна транзакция под общим замком: пишущих потоков немного, а SQLite
    не любит параллельную запись."""
    with _db_lock:
        try:
            yield _db
            _db.commit()
        except Exception:
            _db.rollback()
            raise


SCHEMA = """
create table if not exists users (
  id          integer primary key autoincrement,
  email       text not null unique,
  pw_salt     text not null,
  pw_hash     text not null,
  invite_code text not null unique,
  created_at  real not null
);

create table if not exists sessions (
  token_hash text primary key,
  user_id    integer not null references users(id) on delete cascade,
  created_at real not null,
  expires_at real not null
);

create table if not exists boards (
  id         text primary key,
  name       text not null,
  owner_id   integer not null references users(id) on delete cascade,
  bg         text not null default 'dots',
  version    integer not null default 0,
  created_at real not null,
  updated_at real not null
);

create table if not exists members (
  board_id text not null references boards(id) on delete cascade,
  user_id  integer not null references users(id) on delete cascade,
  role     text not null default 'editor',
  added_at real not null,
  primary key (board_id, user_id)
);

-- По строке на каждый стикер и фигуру: двое, правящие разные объекты,
-- не затирают работу друг друга. Удалённые остаются с deleted = 1,
-- чтобы второй участник узнал об удалении при следующем опросе.
create table if not exists items (
  board_id   text not null references boards(id) on delete cascade,
  id         text not null,
  data       text not null,
  z          integer not null default 0,
  deleted    integer not null default 0,
  version    integer not null default 0,
  updated_by integer references users(id),
  updated_at real not null,
  primary key (board_id, id)
);

create index if not exists items_version_idx on items(board_id, version);
create index if not exists members_user_idx on members(user_id);
create index if not exists sessions_user_idx on sessions(user_id);
"""

with tx() as db:
    db.executescript(SCHEMA)

# ──────────────────────── пароли и сессии ────────────────────────


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=bytes.fromhex(salt),
        n=SCRYPT_N,
        r=8,
        p=1,
        dklen=32,
    )
    return salt, digest.hex()


def password_ok(password: str, salt: str, expected: str) -> bool:
    _, got = hash_password(password, salt)
    return hmac.compare_digest(got, expected)


def token_fingerprint(token: str) -> str:
    """В базе лежит отпечаток, а не сам токен: утечка базы не даёт живых сессий."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_invite_code(db) -> str:
    while True:
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LEN))
        if not db.execute("select 1 from users where invite_code = ?", (code,)).fetchone():
            return code


def new_board_id() -> str:
    return secrets.token_hex(8)


# ──────────────────── простое ограничение попыток ────────────────────

_attempts: dict[str, list[float]] = {}
_attempts_lock = threading.Lock()


def throttle(key: str, limit: int, window: float):
    """Грубая защита от перебора пароля. Счётчик в памяти — при перезапуске
    обнуляется, но свою задачу (замедлить машинный перебор) выполняет."""
    now = time.time()
    with _attempts_lock:
        hits = [t for t in _attempts.get(key, []) if now - t < window]
        hits.append(now)
        _attempts[key] = hits
        if len(_attempts) > 10000:          # не растём бесконечно
            for k in [k for k, v in _attempts.items() if not v or now - v[-1] > window]:
                _attempts.pop(k, None)
        if len(hits) > limit:
            raise HTTPException(429, "Слишком много попыток, подождите минуту")


# ───────────────────────── вспомогательное ─────────────────────────

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+\.[^@\s]+$")


def current_user(authorization: str | None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Нужен вход")
    token = authorization[7:].strip()
    row = _db.execute(
        """select u.id, u.email, u.invite_code, s.expires_at
             from sessions s join users u on u.id = s.user_id
            where s.token_hash = ?""",
        (token_fingerprint(token),),
    ).fetchone()
    if not row:
        raise HTTPException(401, "Нужен вход")
    if row["expires_at"] < time.time():
        with tx() as db:
            db.execute("delete from sessions where token_hash = ?", (token_fingerprint(token),))
        raise HTTPException(401, "Вход устарел, войдите снова")
    return row


def require_member(board_id: str, user_id: int):
    row = _db.execute(
        """select b.id, b.name, b.bg, b.version, b.owner_id, m.role
             from boards b join members m on m.board_id = b.id
            where b.id = ? and m.user_id = ?""",
        (board_id, user_id),
    ).fetchone()
    if not row:
        raise HTTPException(404, "Доска не найдена")
    return row


def board_json(row, owner_email=None):
    return {
        "id": row["id"],
        "name": row["name"],
        "bg": row["bg"],
        "version": row["version"],
        "role": row["role"] if "role" in row.keys() else None,
        "owner_email": owner_email,
    }


def start_session(db, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    db.execute(
        "insert into sessions (token_hash, user_id, created_at, expires_at) values (?,?,?,?)",
        (token_fingerprint(token), user_id, now, now + SESSION_DAYS * 86400),
    )
    db.execute("delete from sessions where expires_at < ?", (now,))
    return token


# ───────────────────────────── модели ─────────────────────────────


class Credentials(BaseModel):
    email: str = Field(max_length=200)
    password: str = Field(max_length=200)


class BoardNew(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class BoardPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    bg: str | None = None


class ItemIn(BaseModel):
    id: str = Field(max_length=64)
    data: dict
    z: int = 0


class ItemsPush(BaseModel):
    items: list[ItemIn] = []
    deleted: list[str] = []


class InviteIn(BaseModel):
    code: str = Field(max_length=32)


# ───────────────────────────── вход ─────────────────────────────


@app.get("/api/health")
def health():
    return {"ok": True}


@app.post("/api/register")
def register(body: Credentials, request: Request):
    # Сначала проверяем форму, и только потом считаем попытку: иначе опечатки
    # в адресе съедают лимит и человек видит «слишком много попыток»
    # вместо подсказки, что именно он написал не так.
    email = body.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Это не похоже на адрес почты")
    if len(body.password) < 8:
        raise HTTPException(400, "Пароль короче восьми символов")
    throttle(f"reg:{request.client.host if request.client else '?'}", 10, 600)

    salt, digest = hash_password(body.password)
    with tx() as db:
        if db.execute("select 1 from users where email = ?", (email,)).fetchone():
            raise HTTPException(409, "Такая почта уже зарегистрирована")
        code = new_invite_code(db)
        cur = db.execute(
            """insert into users (email, pw_salt, pw_hash, invite_code, created_at)
               values (?,?,?,?,?)""",
            (email, salt, digest, code, time.time()),
        )
        token = start_session(db, cur.lastrowid)
        return {"token": token, "user": {"id": cur.lastrowid, "email": email, "invite_code": code}}


@app.post("/api/login")
def login(body: Credentials, request: Request):
    email = body.email.strip().lower()
    throttle(f"log:{request.client.host if request.client else '?'}:{email}", 10, 300)
    row = _db.execute(
        "select id, email, pw_salt, pw_hash, invite_code from users where email = ?", (email,)
    ).fetchone()
    if not row or not password_ok(body.password, row["pw_salt"], row["pw_hash"]):
        raise HTTPException(401, "Неверная почта или пароль")
    with tx() as db:
        token = start_session(db, row["id"])
    return {
        "token": token,
        "user": {"id": row["id"], "email": row["email"], "invite_code": row["invite_code"]},
    }


@app.post("/api/logout")
def logout(authorization: str | None = Header(default=None)):
    if authorization and authorization.lower().startswith("bearer "):
        with tx() as db:
            db.execute(
                "delete from sessions where token_hash = ?",
                (token_fingerprint(authorization[7:].strip()),),
            )
    return {"ok": True}


@app.get("/api/me")
def me(authorization: str | None = Header(default=None)):
    u = current_user(authorization)
    return {"id": u["id"], "email": u["email"], "invite_code": u["invite_code"]}


# ───────────────────────────── доски ─────────────────────────────


@app.get("/api/boards")
def list_boards(authorization: str | None = Header(default=None)):
    u = current_user(authorization)
    rows = _db.execute(
        """select b.id, b.name, b.bg, b.version, b.owner_id, b.updated_at,
                  m.role, o.email as owner_email,
                  (select count(*) from members mm where mm.board_id = b.id) as people
             from boards b
             join members m on m.board_id = b.id and m.user_id = ?
             join users o on o.id = b.owner_id
            order by b.updated_at desc""",
        (u["id"],),
    ).fetchall()
    return {
        "boards": [
            {
                "id": r["id"],
                "name": r["name"],
                "bg": r["bg"],
                "version": r["version"],
                "role": r["role"],
                "mine": r["owner_id"] == u["id"],
                "owner_email": r["owner_email"],
                "people": r["people"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]
    }


@app.post("/api/boards")
def create_board(body: BoardNew, authorization: str | None = Header(default=None)):
    u = current_user(authorization)
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "У доски должно быть название")
    bid, now = new_board_id(), time.time()
    with tx() as db:
        db.execute(
            """insert into boards (id, name, owner_id, bg, version, created_at, updated_at)
               values (?,?,?,'dots',0,?,?)""",
            (bid, name, u["id"], now, now),
        )
        db.execute(
            "insert into members (board_id, user_id, role, added_at) values (?,?,'owner',?)",
            (bid, u["id"], now),
        )
    return {"id": bid, "name": name, "bg": "dots", "version": 0, "role": "owner", "mine": True}


@app.get("/api/boards/{board_id}")
def get_board(board_id: str, authorization: str | None = Header(default=None)):
    u = current_user(authorization)
    b = require_member(board_id, u["id"])
    rows = _db.execute(
        "select id, data, z from items where board_id = ? and deleted = 0 order by z, rowid",
        (board_id,),
    ).fetchall()
    return {
        "id": b["id"],
        "name": b["name"],
        "bg": b["bg"],
        "version": b["version"],
        "role": b["role"],
        "mine": b["owner_id"] == u["id"],
        "items": [dict(json.loads(r["data"]), id=r["id"]) for r in rows],
    }


@app.patch("/api/boards/{board_id}")
def patch_board(board_id: str, body: BoardPatch, authorization: str | None = Header(default=None)):
    u = current_user(authorization)
    require_member(board_id, u["id"])
    sets, args = [], []
    if body.name is not None:
        sets.append("name = ?")
        args.append(body.name.strip())
    if body.bg is not None:
        if body.bg not in ("dots", "grid"):
            raise HTTPException(400, "Фон бывает только 'dots' или 'grid'")
        sets.append("bg = ?")
        args.append(body.bg)
    if not sets:
        return {"ok": True}
    sets.append("updated_at = ?")
    args += [time.time(), board_id]
    with tx() as db:
        db.execute(f"update boards set {', '.join(sets)} where id = ?", args)
    return {"ok": True}


@app.delete("/api/boards/{board_id}")
def delete_board(board_id: str, authorization: str | None = Header(default=None)):
    u = current_user(authorization)
    b = require_member(board_id, u["id"])
    with tx() as db:
        if b["owner_id"] == u["id"]:
            db.execute("delete from boards where id = ?", (board_id,))
        else:
            # не владелец — просто уходит с доски
            db.execute(
                "delete from members where board_id = ? and user_id = ?", (board_id, u["id"])
            )
    return {"ok": True}


# ───────────────────────── объекты доски ─────────────────────────


@app.put("/api/boards/{board_id}/items")
def push_items(board_id: str, body: ItemsPush, authorization: str | None = Header(default=None)):
    u = current_user(authorization)
    b = require_member(board_id, u["id"])
    if not body.items and not body.deleted:
        return {"version": b["version"]}
    now = time.time()
    with tx() as db:
        ver = db.execute("select version from boards where id = ?", (board_id,)).fetchone()[0]
        for it in body.items:
            ver += 1
            db.execute(
                """insert into items (board_id, id, data, z, deleted, version, updated_by, updated_at)
                   values (?,?,?,?,0,?,?,?)
                   on conflict (board_id, id) do update set
                     data = excluded.data, z = excluded.z, deleted = 0,
                     version = excluded.version, updated_by = excluded.updated_by,
                     updated_at = excluded.updated_at""",
                (board_id, it.id, json.dumps(it.data, ensure_ascii=False), it.z, ver, u["id"], now),
            )
        for dead in body.deleted:
            ver += 1
            db.execute(
                """insert into items (board_id, id, data, z, deleted, version, updated_by, updated_at)
                   values (?,?,'{}',0,1,?,?,?)
                   on conflict (board_id, id) do update set
                     deleted = 1, version = excluded.version,
                     updated_by = excluded.updated_by, updated_at = excluded.updated_at""",
                (board_id, dead, ver, u["id"], now),
            )
        db.execute("update boards set version = ?, updated_at = ? where id = ?", (ver, now, board_id))
    return {"version": ver}


@app.get("/api/boards/{board_id}/changes")
def changes(board_id: str, since: int = 0, authorization: str | None = Header(default=None)):
    """Что изменилось после версии since — этим опрашивает открытая доска."""
    u = current_user(authorization)
    b = require_member(board_id, u["id"])
    rows = _db.execute(
        """select id, data, z, deleted, updated_by from items
            where board_id = ? and version > ? order by version""",
        (board_id, since),
    ).fetchall()
    return {
        "version": b["version"],
        "name": b["name"],
        "bg": b["bg"],
        "items": [
            dict(json.loads(r["data"]), id=r["id"])
            for r in rows
            if not r["deleted"] and r["updated_by"] != u["id"]
        ],
        "deleted": [r["id"] for r in rows if r["deleted"]],
    }


# ───────────────────────── участники ─────────────────────────


@app.get("/api/boards/{board_id}/members")
def board_members(board_id: str, authorization: str | None = Header(default=None)):
    u = current_user(authorization)
    require_member(board_id, u["id"])
    rows = _db.execute(
        """select u.id, u.email, m.role from members m join users u on u.id = m.user_id
            where m.board_id = ? order by m.added_at""",
        (board_id,),
    ).fetchall()
    return {"members": [{"id": r["id"], "email": r["email"], "role": r["role"]} for r in rows]}


@app.post("/api/boards/{board_id}/invite")
def invite(board_id: str, body: InviteIn, authorization: str | None = Header(default=None)):
    """Добавление по личному коду. Отвечаем только «есть» или «нет»: перебрать
    коды и так выяснить чужие адреса нельзя."""
    u = current_user(authorization)
    b = require_member(board_id, u["id"])
    if b["owner_id"] != u["id"]:
        raise HTTPException(403, "Приглашать может только владелец доски")
    throttle(f"inv:{u['id']}", 20, 300)

    code = body.code.strip().upper().replace(" ", "")
    row = _db.execute("select id, email from users where invite_code = ?", (code,)).fetchone()
    if not row:
        raise HTTPException(404, "Такого кода нет")
    if row["id"] == u["id"]:
        raise HTTPException(400, "Это ваш собственный код")
    with tx() as db:
        db.execute(
            "insert or ignore into members (board_id, user_id, role, added_at) values (?,?,'editor',?)",
            (board_id, row["id"], time.time()),
        )
    return {"email": row["email"]}


@app.delete("/api/boards/{board_id}/members/{user_id}")
def remove_member(
    board_id: str, user_id: int, authorization: str | None = Header(default=None)
):
    u = current_user(authorization)
    b = require_member(board_id, u["id"])
    if b["owner_id"] != u["id"] and user_id != u["id"]:
        raise HTTPException(403, "Убирать участников может только владелец")
    if user_id == b["owner_id"]:
        raise HTTPException(400, "Владельца убрать нельзя")
    with tx() as db:
        db.execute("delete from members where board_id = ? and user_id = ?", (board_id, user_id))
    return {"ok": True}


@app.exception_handler(HTTPException)
def pretty_errors(request: Request, exc: HTTPException):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
