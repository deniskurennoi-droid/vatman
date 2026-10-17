"""Сквозная проверка сервера Ватмана: два человека, общая доска, правки."""
import json
import urllib.error
import urllib.request

import os
BASE = os.environ.get("VATMAN_API", "http://127.0.0.1:8000").rstrip("/")
ok = bad = 0

# уникальные адреса, чтобы прогон можно было повторять на той же базе
import time as _t
TAG = str(int(_t.time() * 1000))[-9:]
MAIL_A = f"denis{TAG}@example.com"
MAIL_B = f"anna{TAG}@example.com"


def call(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def check(label, got, want):
    global ok, bad
    if got == want:
        ok += 1
        print(f"  ок    {label}")
    else:
        bad += 1
        print(f"  ПЛОХО {label}: получили {got!r}, ждали {want!r}")


print("— регистрация и вход —")
s, a = call("POST", "/api/register", {"email": " " + MAIL_A.upper(), "password": "parol12345"})
check("регистрация A", s, 200)
A = a["token"]
codeA = a["user"]["invite_code"]
check("почта приведена к нижнему регистру", a["user"]["email"], MAIL_A)
check("код из 8 символов", len(codeA), 8)

s, b = call("POST", "/api/register", {"email": MAIL_B, "password": "parol12345"})
check("регистрация B", s, 200)
B = b["token"]
codeB = b["user"]["invite_code"]
check("коды разные", codeA != codeB, True)

s, _ = call("POST", "/api/register", {"email": MAIL_A, "password": "parol12345"})
check("повторная почта отбита", s, 409)
s, _ = call("POST", "/api/register", {"email": "кто-то", "password": "parol12345"})
check("кривая почта отбита", s, 400)
s, _ = call("POST", "/api/register", {"email": "x" + TAG + "@y.ru", "password": "korotko"})
check("короткий пароль отбит", s, 400)
s, _ = call("POST", "/api/login", {"email": MAIL_A, "password": "nevernyj"})
check("неверный пароль отбит", s, 401)
s, r = call("POST", "/api/login", {"email": MAIL_A, "password": "parol12345"})
check("вход верным паролем", s, 200)
s, r = call("GET", "/api/me", token=A)
check("свой профиль", r.get("email"), MAIL_A)
s, _ = call("GET", "/api/me")
check("без токена не пускает", s, 401)
s, _ = call("GET", "/api/me", token="poddelka-nevernyj-token")
check("с чужим токеном не пускает", s, 401)

print("— доски —")
s, brd = call("POST", "/api/boards", {"name": "  Спринт 13  "}, token=A)
check("доска создана", s, 200)
BID = brd["id"]
check("название обрезано", brd["name"], "Спринт 13")
s, _ = call("POST", "/api/boards", {"name": "   "}, token=A)
check("пустое название отбито", s, 400)
s, r = call("GET", "/api/boards", token=A)
check("у A одна доска", len(r["boards"]), 1)
check("доска своя", r["boards"][0]["mine"], True)
check("в доске один человек", r["boards"][0]["people"], 1)
s, r = call("GET", "/api/boards", token=B)
check("у B досок нет", len(r["boards"]), 0)
s, _ = call("GET", f"/api/boards/{BID}", token=B)
check("чужая доска не открывается", s, 404)

print("— приглашение по коду —")
s, _ = call("POST", f"/api/boards/{BID}/invite", {"code": "ZZZZZZZZ"}, token=A)
check("несуществующий код", s, 404)
s, _ = call("POST", f"/api/boards/{BID}/invite", {"code": codeA}, token=A)
check("свой собственный код", s, 400)
s, r = call("POST", f"/api/boards/{BID}/invite", {"code": codeB.lower()}, token=A)
check("приглашение по коду (регистр не важен)", s, 200)
check("вернулась почта приглашённого", r["email"], MAIL_B)
s, r = call("GET", "/api/boards", token=B)
check("доска появилась у B", len(r["boards"]), 1)
check("для B она не своя", r["boards"][0]["mine"], False)
check("видно владельца", r["boards"][0]["owner_email"], MAIL_A)
check("в доске двое", r["boards"][0]["people"], 2)
s, _ = call("POST", f"/api/boards/{BID}/invite", {"code": codeA}, token=B)
check("не владелец приглашать не может", s, 403)

print("— правки с двух сторон —")
s, r = call("PUT", f"/api/boards/{BID}/items", {
    "items": [{"id": "s1", "data": {"type": "sticky", "x": 0, "y": 0, "text": "от Анны"}, "z": 0},
              {"id": "s2", "data": {"type": "sticky", "x": 200, "y": 0, "text": "второй"}, "z": 1}]
}, token=B)
check("B положил два стикера", s, 200)
v1 = r["version"]
s, r = call("GET", f"/api/boards/{BID}/changes?since=0", token=A)
check("A видит правки B", len(r["items"]), 2)
check("удалённых нет", r["deleted"], [])
s, r = call("GET", f"/api/boards/{BID}/changes?since=0", token=B)
check("свои правки не возвращаются эхом", len(r["items"]), 0)

s, r = call("PUT", f"/api/boards/{BID}/items", {
    "items": [{"id": "s3", "data": {"type": "sticky", "text": "от Дениса"}, "z": 2}],
    "deleted": ["s1"],
}, token=A)
check("A добавил свой и удалил чужой", s, 200)
s, r = call("GET", f"/api/boards/{BID}/changes?since={v1}", token=B)
check("B видит новый стикер A", [i["id"] for i in r["items"]], ["s3"])
check("B видит удаление", r["deleted"], ["s1"])
s, r = call("GET", f"/api/boards/{BID}", token=B)
check("в доске осталось два объекта", sorted(i["id"] for i in r["items"]), ["s2", "s3"])

print("— фон и название —")
s, _ = call("PATCH", f"/api/boards/{BID}", {"bg": "полосочки"}, token=A)
check("неизвестный фон отбит", s, 400)
s, _ = call("PATCH", f"/api/boards/{BID}", {"bg": "grid", "name": "Спринт 14"}, token=B)
check("участник может менять фон", s, 200)
s, r = call("GET", f"/api/boards/{BID}", token=A)
check("фон сохранён", r["bg"], "grid")
check("название сохранено", r["name"], "Спринт 14")

print("— уход и удаление —")
s, _ = call("DELETE", f"/api/boards/{BID}/members/{a['user']['id']}", token=B)
check("не владелец никого не убирает", s, 403)
s, _ = call("DELETE", f"/api/boards/{BID}/members/{a['user']['id']}", token=A)
check("владелец не убирает сам себя", s, 400)
s, _ = call("DELETE", f"/api/boards/{BID}/members/{b['user']['id']}", token=A)
check("владелец убирает участника", s, 200)
s, r = call("GET", "/api/boards", token=B)
check("убранный доску потерял", len(r["boards"]), 0)
s, r = call("POST", f"/api/boards/{BID}/invite", {"code": codeB}, token=A)
check("вернули обратно", s, 200)
s, _ = call("DELETE", f"/api/boards/{BID}", token=B)
check("B уходит с доски", s, 200)
s, r = call("GET", "/api/boards", token=B)
check("у B снова нет досок", len(r["boards"]), 0)
s, r = call("GET", "/api/boards", token=A)
check("у A доска на месте", len(r["boards"]), 1)
s, r = call("GET", f"/api/boards/{BID}/members", token=A)
check("в составе остался один", len(r["members"]), 1)
s, _ = call("GET", f"/api/boards/{BID}", token=B)
check("ушедший доску не видит", s, 404)

print("— выход из аккаунта —")
s, _ = call("POST", "/api/logout", token=A)
check("выход", s, 200)
s, _ = call("GET", "/api/me", token=A)
check("токен после выхода мёртв", s, 401)

print(f"\nитого: ок {ok}, плохо {bad}")
