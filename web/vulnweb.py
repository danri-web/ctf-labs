#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""比赛热身：一个故意有 5 个洞的小站（纯标准库，Windows / Kali 都能跑）。

用法：
    python3 vulnweb.py            # 默认 8000 端口
    python3 vulnweb.py 9000       # 换端口
然后浏览器开 http://127.0.0.1:8000/

⚠️ 只在本机练习用，不要放到公网、不要留在比赛环境里。

五个洞（别先看源码，先黑盒打）：
    L1 /login    SQL 注入（字符串拼接）
    L2 /download 路径穿越（任意文件读）
    L3 /ping     命令注入（shell=True）
    L4 /admin    弱口令
    L5 /hidden/  robots.txt 里泄露的目录
"""
import html
import io
import os
import sqlite3
import subprocess
import sys
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_run")
FLAGS = os.path.join(BASE, "flags")
FILES = os.path.join(BASE, "files")
HIDDEN = os.path.join(BASE, "hidden")

FLAG_TEXT = {
    1: "flag{sqli_login_bypass}",
    2: "flag{path_traversal_read_me}",
    3: "flag{command_injection_ping}",
    4: "flag{weak_admin_password}",
    5: "flag{robots_hides_a_dir}",
}

STYLE = """
body{background:#12141a;color:#dfe3ea;font-family:Consolas,"Microsoft YaHei",monospace;
     max-width:820px;margin:40px auto;padding:0 18px;line-height:1.7}
h1{color:#ffd166;font-size:22px} a{color:#6cb6ff}
code,pre{background:#0a0c10;color:#8ee08e;padding:2px 6px;border-radius:4px}
pre{padding:12px;overflow:auto;white-space:pre-wrap}
input{background:#0a0c10;color:#8ee08e;border:1px solid #3a4150;padding:7px;width:220px}
input[type=submit]{background:#2b6cb0;color:#fff;border:0;cursor:pointer}
.box{border:1px solid #2c3240;border-radius:8px;padding:14px 16px;margin:14px 0}
"""


def esc(s):
    return html.escape(str(s))


def page(title, body):
    return ("<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
            "<title>%s</title><style>%s</style></head><body>%s</body></html>"
            % (esc(title), STYLE, body))


def init_data():
    os.makedirs(FLAGS, exist_ok=True)
    os.makedirs(FILES, exist_ok=True)
    os.makedirs(HIDDEN, exist_ok=True)
    for n, t in FLAG_TEXT.items():
        with open(os.path.join(FLAGS, "flag%d.txt" % n), "w", encoding="utf-8") as f:
            f.write(t + "\n")
    with open(os.path.join(FILES, "readme.txt"), "w", encoding="utf-8") as f:
        f.write("这是公开的说明书。试试把 file 参数改成别的东西。\n")
    with open(os.path.join(HIDDEN, "flag5.txt"), "w", encoding="utf-8") as f:
        f.write(FLAG_TEXT[5] + "\n")
    # 故意"泄露"的备份包：里面是本站源码
    src = os.path.abspath(__file__)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(src, "vulnweb.py")
    with open(os.path.join(FILES, "backup.zip"), "wb") as f:
        f.write(buf.getvalue())


DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("CREATE TABLE users(name TEXT, pass TEXT)")
DB.executemany("INSERT INTO users VALUES(?,?)",
               [("admin", "admin123"), ("guest", "guest")])
DB.commit()


def read_flag(n):
    with open(os.path.join(FLAGS, "flag%d.txt" % n), encoding="utf-8") as f:
        return f.read().strip()


INDEX = """<h1>热身靶场 · 五道小菜</h1>
<div class="box">
<p>目标：拿到 5 个 <code>flag{...}</code>。全部是简单题，考的是「别漏看」。</p>
<ul>
<li><a href="/login">/login</a> — 登录</li>
<li><a href="/download?file=readme.txt">/download?file=readme.txt</a> — 下载文件</li>
<li><a href="/ping?ip=127.0.0.1">/ping?ip=127.0.0.1</a> — 网络诊断</li>
<li><a href="/admin">/admin</a> — 管理后台</li>
<li><a href="/robots.txt">/robots.txt</a></li>
</ul>
<p style="color:#8b93a7">提示：从 robots.txt 和源码开始永远不亏。</p>
</div>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Warmup/1.0"

    def log_message(self, fmt, *args):
        pass

    def send_html(self, text, code=200):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_bytes(self, data, ctype="application/octet-stream", download=None):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if download:
            self.send_header("Content-Disposition", "attachment; filename=%s" % download)
        self.end_headers()
        self.wfile.write(data)

    # ---------------------------------------------------------------- GET
    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        p = u.path

        if p == "/":
            return self.send_html(page("热身靶场", INDEX))

        if p == "/robots.txt":
            return self.send_bytes(b"User-agent: *\nDisallow: /hidden/\n", "text/plain")

        if p == "/login":
            return self.send_html(page("登录", """<h1>登录</h1>
<div class="box"><form method="post" action="/login">
  用户名 <input name="u"> 密码 <input name="p" type="password">
  <input type="submit" value="登录">
</form></div><p><a href="/">返回</a></p>"""))

        if p == "/admin":
            return self.send_html(page("后台", """<h1>管理后台</h1>
<div class="box"><form method="post" action="/admin">
  用户名 <input name="u"> 密码 <input name="p" type="password">
  <input type="submit" value="进入">
</form></div><p><a href="/">返回</a></p>"""))

        if p == "/download":
            name = q.get("file", "")
            path = os.path.join(FILES, name)          # ← 洞 2：没做任何规范化
            try:
                with open(path, "rb") as f:
                    data = f.read()
            except OSError as e:
                return self.send_html(page("下载失败", "<h1>下载失败</h1><pre>%s</pre>" % esc(e)), 404)
            return self.send_bytes(data, "application/octet-stream", os.path.basename(name))

        if p == "/ping":
            ip = q.get("ip", "")
            if os.name == "nt":
                cmd = "ping -n 1 " + ip
            else:
                cmd = "ping -c 1 " + ip
            try:
                out = subprocess.run(cmd, shell=True, capture_output=True,
                                     text=True, errors="replace", timeout=10)
                text = (out.stdout or "") + (out.stderr or "")
            except subprocess.TimeoutExpired:
                text = "超时"
            return self.send_html(page("ping", "<h1>网络诊断</h1><div class='box'>"
                                       "<pre>%s</pre></div><p><a href='/'>返回</a></p>" % esc(text)))

        if p.startswith("/hidden/"):
            return self.serve_static(os.path.join(BASE, p.lstrip("/")))

        if p == "/backup.zip":
            with open(os.path.join(FILES, "backup.zip"), "rb") as f:
                return self.send_bytes(f.read(), "application/zip", "backup.zip")

        return self.send_html(page("404", "<h1>404</h1><p>没有这个页面。</p>"), 404)

    def serve_static(self, path):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return self.send_html(page("404", "<h1>404</h1>"), 404)
        return self.send_bytes(data, "text/plain; charset=utf-8")

    # ---------------------------------------------------------------- POST
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        form = {k: v[0] for k, v in parse_qs(body).items()}
        p = urlparse(self.path).path

        if p == "/login":
            u = form.get("u", "")
            pw = form.get("p", "")
            sql = "SELECT name FROM users WHERE name='%s' AND pass='%s'" % (u, pw)   # ← 洞 1
            try:
                row = DB.execute(sql).fetchone()
            except sqlite3.Error as e:
                return self.send_html(page("登录", "<h1>登录</h1><div class='box'>"
                                           "<pre>SQL 错误：%s</pre></div>" % esc(e)))
            if not row:
                return self.send_html(page("登录失败", "<h1>登录失败</h1>"
                                           "<div class='box'>用户名或密码不对。</div>"))
            if row[0] == "admin":
                return self.send_html(page("欢迎", "<h1>欢迎回来，admin</h1><div class='box'>"
                                           "<p>%s</p></div>" % esc(read_flag(1))))
            return self.send_html(page("欢迎", "<h1>欢迎，%s</h1>" % esc(row[0])))

        if p == "/admin":
            if form.get("u") == "admin" and form.get("p") == "admin123":
                return self.send_html(page("后台", "<h1>后台</h1><div class='box'>"
                                           "<p>%s</p></div>" % esc(read_flag(4))))
            return self.send_html(page("后台", "<h1>后台</h1><div class='box'>口令不对。</div>"))

        return self.send_html(page("404", "<h1>404</h1>"), 404)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    init_data()
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print("热身靶场: http://127.0.0.1:%d/  (Ctrl+C 停止)" % port)
    srv.serve_forever()


if __name__ == "__main__":
    main()
