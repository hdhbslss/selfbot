import base64
import email
import imaplib
import json
import os
import random
import re
import string
import sys
import time
from email.header import decode_header

import requests

# ════════════════════════════════════════════════════════════
#  常數
# ════════════════════════════════════════════════════════════

DISCORD_API = "https://discord.com/api/v9"
REGISTER_URL = f"{DISCORD_API}/auth/register"
ME_URL = f"{DISCORD_API}/users/@me"
OPEN_DM = f"{DISCORD_API}/users/@me/channels"
SEND_MSG = f"{DISCORD_API}/channels/{{cid}}/messages"
INVITE_RESOLVE = f"{DISCORD_API}/invites/{{code}}?with_counts=true"
INVITE_ACCEPT = f"{DISCORD_API}/invites/{{code}}"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0.0.0 Safari/537.36")

BANNER = r"""
 ██╗    ██╗███████╗██╗      ██████╗ ██████╗ ███╗   ███╗███████╗
 ██║    ██║██╔════╝██║     ██╔════╝██╔═══██╗████╗ ████║██╔════╝
 ██║ █╗ ██║█████╗  ██║     ██║     ██║   ██║██╔████╔██║█████╗
 ██║███╗██║██╔══╝  ██║     ██║     ██║   ██║██║╚██╔╝██║██╔══╝
 ╚███╔███╔╝███████╗███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║███████╗
  ╚══╝╚══╝ ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝
"""

MENU = """
  ┌─────────────────────────────────────────────┐
  │  歡迎你回來                                  │
  ├─────────────────────────────────────────────┤
  │   [1]  自動產生帳號 + Token                  │
  │   [2]  自動刷伺服器人數                      │
  │   [3]  自動私訊刷屏                          │
  │   [0]  離開                                   │
  └─────────────────────────────────────────────┘
"""


# ════════════════════════════════════════════════════════════
#  共通工具
# ════════════════════════════════════════════════════════════

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def draw():
    clear()
    print("\033[96m" + BANNER + "\033[0m")
    print(MENU)


def ask(prompt="  > "):
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return "0"


def pause_back():
    ask("\n  按 Enter 回主選單...")


def cfg():
    with open("config.json", "r", encoding="utf-8") as f:
        return json.load(f)


def load_proxies(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return lines or [None]
    except FileNotFoundError:
        return [None]


def load_lines(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [l.rstrip("\n") for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        return []


def read_tokens_multiline():
    print("  請貼上 Token（一行一個）。貼完後按一次 Enter 結束：")
    tokens = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "":
            break
        tokens.append(line.strip())
    return tokens


def rand_pw(n=14):
    return "".join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=n))


def rand_user():
    return f"user{random.randint(100000, 999999)}"


def fingerprint():
    return {
        "os": "Windows", "browser": "Chrome", "device": "",
        "system_locale": "en-US", "browser_user_agent": UA,
        "browser_version": "124.0.0.0", "os_version": "10",
        "referrer": "", "referring_domain": "",
        "referrer_current": "", "referring_domain_current": "",
        "release_channel": "stable", "client_build_number": 289000,
        "client_event_source": None,
    }


def discord_headers(referer="https://discord.com/register"):
    sp = base64.b64encode(json.dumps(fingerprint()).encode()).decode()
    return {
        "User-Agent": UA, "Content-Type": "application/json",
        "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://discord.com", "Referer": referer,
        "X-Super-Properties": sp, "X-Discord-Locale": "en-US",
        "X-Debug-Options": "bugReporterEnabled",
    }


def auth_headers(token):
    return {
        "User-Agent": UA, "Authorization": token,
        "Content-Type": "application/json",
        "Accept": "*/*", "Origin": "https://discord.com",
        "Referer": "https://discord.com/channels/@me",
    }


# ════════════════════════════════════════════════════════════
#  hCaptcha
# ════════════════════════════════════════════════════════════

def solve_hcaptcha(c):
    s = c["solver"]
    payload = {
        "clientKey": s["api_key"],
        "task": {"type": "HCaptchaTaskProxyless",
                 "websiteURL": s["siteurl"], "websiteKey": s["sitekey"]},
    }
    r = requests.post("https://api.capsolver.com/createTask",
                      json=payload, timeout=30).json()
    if r.get("errorId", 1) != 0:
        raise RuntimeError(f"createTask 失敗: {r}")
    task_id = r["taskId"]
    for _ in range(90):
        time.sleep(2)
        poll = requests.post("https://api.capsolver.com/getTaskResult",
                             json={"clientKey": s["api_key"], "taskId": task_id},
                             timeout=30).json()
        if poll.get("status") == "ready":
            return poll["solution"]["gRecaptchaResponse"]
        if poll.get("errorId", 0) != 0:
            raise RuntimeError(f"getTaskResult 失敗: {poll}")
    raise TimeoutError("hCaptcha 逾時")


# ════════════════════════════════════════════════════════════
#  Email 收信
# ════════════════════════════════════════════════════════════

def decode_mime(s):
    if not s:
        return ""
    out = ""
    for text, enc in decode_header(s):
        if isinstance(text, bytes):
            out += text.decode(enc or "utf-8", errors="ignore")
        else:
            out += text
    return out


def fetch_verify_link(c, addr, timeout=None, interval=None):
    e = c["email"]
    timeout = timeout or e.get("poll_timeout", 180)
    interval = interval or e.get("poll_interval", 6)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            M = imaplib.IMAP4_SSL(e["imap_host"], e["imap_port"])
            M.login(e["imap_user"], e["imap_pass"])
            M.select("INBOX")
            _, data = M.search(None, f'(TO "{addr}")')
            ids = data[0].split()
            for mid in reversed(ids[-10:]):
                _, md = M.fetch(mid, "(RFC822)")
                msg = email.message_from_bytes(md[0][1])
                subject = decode_mime(msg.get("Subject", ""))
                if "discord" not in subject.lower() and "verify" not in subject.lower():
                    continue
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() in ("text/html", "text/plain"):
                            body += part.get_payload(decode=True).decode("utf-8", errors="ignore")
                else:
                    body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
                m = re.search(r"https://click\.discord\.com/ls/click\?upn=[^\s\"'<>]+", body) \
                    or re.search(r"https://discord\.com/verify[^\s\"'<>]+", body)
                if m:
                    M.logout()
                    return m.group(0).replace("&amp;", "&")
            M.logout()
        except Exception:
            pass
        time.sleep(interval)
    raise TimeoutError("等不到驗證信")


def make_email(c, i):
    e = c["email"]
    if e["mode"] == "imap_catchall":
        return f"dc{int(time.time())}{i}{random.randint(100,999)}@{e['domain']}"
    if e["mode"] == "imap_gmail":
        base, _, _ = e["imap_user"].partition("@")
        return f"{base}+dc{int(time.time())}{i}@gmail.com"
    raise ValueError(f"未知 email mode: {e['mode']}")


# ════════════════════════════════════════════════════════════
#  功能 1：自動產帳號 + Token
# ════════════════════════════════════════════════════════════

def register_one(c, proxy, addr, do_verify=True):
    pw = rand_pw()
    uname = rand_user()
    birth = f"{random.randint(1985,2000)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}"
    cap = solve_hcaptcha(c)
    px = {"http": proxy, "https": proxy} if proxy else None

    body = {
        "email": addr, "password": pw, "username": uname,
        "date_of_birth": birth, "gift_code_sku_id": None, "invite": None,
        "consent": True, "captcha_key": cap,
        "promotional_email_opt_in": False,
        "unique_username_registration": True,
    }
    r = requests.post(REGISTER_URL, json=body, headers=discord_headers(),
                      proxies=px, timeout=30)
    if r.status_code != 200:
        try: err = r.json()
        except Exception: err = r.text
        return {"ok": False, "email": addr, "error": err,
                "token": None, "valid": False, "verified": False}

    token = r.json().get("token")

    valid = False
    if token:
        me = requests.get(ME_URL,
                          headers={"User-Agent": UA, "Authorization": token},
                          proxies=px, timeout=30)
        valid = me.status_code == 200

    verified = False
    if do_verify and token:
        try:
            link = fetch_verify_link(c, addr)
            v = requests.get(link, headers={"User-Agent": UA},
                             proxies=px, timeout=30, allow_redirects=True)
            verified = v.status_code == 200
        except Exception:
            pass

    return {"ok": True, "email": addr, "password": pw, "username": uname,
            "token": token, "valid": valid, "verified": verified}


def save_results(rows, path="results.json"):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


def run_autoreg(c):
    ac = c.get("autoreg", {})
    proxies = load_proxies(ac.get("proxy_file", "proxies.txt"))
    delay = ac.get("delay_between", [4, 9])

    while True:
        n = input("  要產生幾個帳號 Token？（1~1000）：").strip()
        if not n.isdigit():
            print("  [!] 請輸入數字。")
            continue
        n = int(n)
        if n < 1 or n > 1000:
            print("  [!] 範圍是 1 到 1000。")
            continue
        break

    print(f"\n  開始產生 {n} 個帳號...\n")

    rows = []
    tokens_out = []

    for i in range(n):
        addr = make_email(c, i)
        try:
            res = register_one(c, proxies[i % len(proxies)], addr)
        except Exception as ex:
            res = {"ok": False, "email": addr, "error": str(ex),
                   "token": None, "valid": False, "verified": False}
        rows.append(res)

        if res.get("token"):
            tokens_out.append(res["token"])
            print(f"  [{i+1}/{n}] ✓ {addr}")
        else:
            print(f"  [{i+1}/{n}] ✗ {addr} — {str(res.get('error'))[:60]}")

        if (i + 1) % 5 == 0:
            save_results(rows)

        time.sleep(random.uniform(delay[0], delay[1]))

    save_results(rows)

    print(f"\n  完成。成功 {len(tokens_out)}/{n} 個。")
    print("\n  ─────── 以下是所有 Token（複製用）───────\n")
    for t in tokens_out:
        print(t)
    print("\n  ────────────────────────────────────────")
    print("  已存檔：results.json")


# ════════════════════════════════════════════════════════════
#  功能 2：刷伺服器人數
# ════════════════════════════════════════════════════════════

def resolve_invite(code, proxy=None):
    px = {"http": proxy, "https": proxy} if proxy else None
    r = requests.get(INVITE_RESOLVE.format(code=code),
                     headers={"User-Agent": UA}, proxies=px, timeout=30)
    return r.json() if r.status_code == 200 else None


def join_invite(token, code, proxy=None):
    px = {"http": proxy, "https": proxy} if proxy else None
    r = requests.post(INVITE_ACCEPT.format(code=code),
                      headers=auth_headers(token),
                      json={}, proxies=px, timeout=30)
    if r.status_code in (200, 204):
        return {"ok": True}
    try: err = r.json()
    except Exception: err = r.text
    return {"ok": False, "status": r.status_code, "error": err}


def run_massjoin(c):
    mj = c.get("massjoin", {})
    proxies = load_proxies(mj.get("proxy_file", "proxies.txt"))
    delay = in m (j.get("delay_between", [2003, ,6])

    invite = input("   請201貼上 Discord 伺服器邀請連結：").strip()
    if not invite:
        print("  [!] 沒有輸入。")
        return
    code = invite.rstrip("/").split("/")[-1]

    info = resolve_invite(code)
    if not info:
        print(f"  [!] 無法解析邀請碼：{code}")
        return
    print(f"\n  伺服器：{info.get('guild', {}).get('name', '未知')}")
    print(f"  目前人數：{info.get('approximate_member_count', '?')}\n")

    tokens = read_tokens_multiline()
    if not tokens:
        print("  [!] 沒有偵測到任何 Token。")
        return

    print(f"\n  總共偵測到 {len(tokens)} 個帳號 Token。")
    ask("  確定要繼續？按 Enter 繼續...")

    print()
    ok = 0
    for i, tk in enumerate(tokens):
        res = join_invite(tk, code, proxies[i % len(proxies)])
        if res.get("ok"):
            ok += 1
            print(f"  [{i+1}/{len(tokens)}] ✓ 加入")
        else:
            print(f"  [{i+1}/{len(tokens)}] ✗ {res.get('status')} {str(res.get('error'))[:60]}")
        time.sleep(random.uniform(delay[0], delay[1]))

    info2 = resolve_invite(code)
    print(f"\n  完成：{ok}/{len(tokens)} 成功")
    if info2:
        print(f"  目前人數：{info2.get('approximate_member_count', '?')}")


# ════════════════════════════════════════════════════════════
#  功能 3：私訊刷屏（訊息可自訂）
# ════════════════════════════════════════════════════════════

def open_dm(token, recipient_id, proxy=None):
    px = {"http": proxy, "https": proxy} if proxy else None
    r = requests.post(OPEN_DM, headers=auth_headers(token),
                      json={"recipient_id": str(recipient_id)},
                      proxies=px, timeout=30)
    if r.status_code in (200, 201):
        return r.json().get("id")
    return None


def send_dm(token, cid, content, proxy=None):
    px = {"http": proxy, "https": proxy} if proxy else None
    r = requests.post(SEND_MSG.format(cid=cid),
                      headers=auth_headers(token),
                      json={"content": content, "tts": False},
                      proxies=px, timeout=30)
    if r.status_code):
        return {"ok": True}
    try: err = r.json()
    except Exception: err = r.text
    return {"ok": False, "status": r.status_code, "error": err}


def run_massdm(c):
    mj = c.get("massdm", {})
    proxies = load_proxies(mj.get("proxy_file", "proxies.txt"))
    delay = mj.get("delay_between", [1.5, 3.5])
    repeat = int(mj.get("repeat", 10))

    target = input("  請輸入目標的 ID 或名稱：").strip()
    if not target:
        print("  [!] 沒有輸入。")
        return

    if not target.isdigit():
        print(f"\n  [!] 「{target}」不是純數字 ID。")
        print("      請開啟 Discord 開發者模式 → 對目標按右鍵 → 複製使用者 ID")
        manual = input("      或直接手動貼上他的 ID：").strip()
        if not manual.isdigit():
            print("  [!] 無效 ID，中止。")
            return
        target = manual

    # ─── 訊息來源選擇 ───
    print("\n  訊息來源：")
    print("   [1] 從 dm_messages.txt 隨機抽")
    print("   [2] 手動輸入一條（重複發同一條）")
    print("   [3] 手動輸入多條（隨機抽）")
    src = input("  > ").strip() or "1"

    if src == "1":
        messages = load_lines(mj.get("message_file", "dm_messages.txt")) \
            or ["嗨", "在嗎", "安安", "打擾了", "你好"]
        print(f"  → 從檔案載入 {len(messages)} 條訊息")

    elif src == "2":
        one = input("  請輸入要發送的訊息：").strip()
        if not one:
            print("  [!] 空訊息，中止。")
            return
        messages = [one]
        print(f"  → 使用單一訊息：{one[:40]}")

    elif src == "3":
        print("  請逐行輸入訊息（一行一條）。貼完後按一次 Enter 結束：")
        messages = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip() == "":
                break
            messages.append(line.rstrip("\n"))
        if not messages:
            print("  [!] 沒有偵測到任何訊息。")
            return
        print(f"  → 載入 {len(messages)} 條訊息")

    else:
        print("  [!] 無效選擇，中止。")
        return

    # ─── 每個 token 要發幾條 ───
    r_in = input(f"\n  每個 Token 要發幾條？（預設 {repeat}）：").strip()
    if r_in.isdigit() and int(r_in) >= 1:
        repeat = int(r_in)

    tokens = read_tokens_multiline()
    if not tokens:
        print("  [!] 沒有偵測到任何 Token。")
        return

    print(f"\n  總共偵測到 {len(tokens)} 個帳號 Token。")
    print(f"  目標 ID：{target}")
    print(f"  每個 Token 發送：{repeat} 條")
    print(f"  訊息池：{len(messages)} 條")
    ask("  確定要繼續？按 Enter 繼續...")

    print()
    total_ok = 0
    total_sent = 0

    for ti, tk in enumerate(tokens):
        proxy = proxies[ti % len(proxies)]
        cid = open_dm(tk, target, proxy)
        if not cid:
            print(f"  [{ti+1}/{len(tokens)}] ✗ 開不了 DM（對方關私訊 / token 死）")
            continue
        print(f"  [{ti+1}/{len(tokens)}] ✓ DM 已開")

        for k in range(repeat):
            content = random.choice(messages)
            res = send_dm(tk, cid, content, proxy)
            total_sent += 1
            if res.get("ok"):
                total_ok += 1
            if res.get("status") == 429:
                time.sleep(5)
            time.sleep(random.uniform(delay[0], delay[1]))

    print(f"\n  完成：送出 {total_ok}/{total_sent} 條成功")


# ════════════════════════════════════════════════════════════
#  主控台
# ════════════════════════════════════════════════════════════

def main():
    while True:
        draw()
        choice = ask()

        if choice == "1":
            clear()
            print("\033[96m" + BANNER + "\033[0m")
            print("\n  → 自動產生帳號 + Token\n")
            try:
                run_autoreg(cfg())
            except Exception as e:
                print(f"\n  [!] 執行錯誤：{e}")
            pause_back()

        elif choice == "2":
            clear()
            print("\033[96m" + BANNER + "\033[0m")
            print("\n  → 自動刷伺服器人數\n")
            try:
                run_massjoin(cfg())
            except Exception as e:
                print(f"\n  [!] 執行錯誤：{e}")
            pause_back()

        elif choice == "3":
            clear()
            print("\033[96m" + BANNER + "\033[0m")
            print("\n  → 自動私訊刷屏\n")
            try:
                run_massdm(cfg())
            except Exception as e:
                print(f"\n  [!] 執行錯誤：{e}")
            pause_back()

        elif choice == "0":
            clear()
            print("\033[96m" + BANNER + "\033[0m")
            print("\n  掰。\n")
            sys.exit(0)

        else:
            time.sleep(0.4)


if __name__ == "__main__":
    main()
