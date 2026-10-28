#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Linux 命令 10 题判分（在本目录跑：python3 check.py）

答案不写死在这里 —— 每次都从 ~/ctfdrill 现场读出来比对，
所以 setup.sh 改了内容也不会判错（断言的是关系，不是快照）。
"""
import base64
import os
import sys
import tarfile
import time
import zipfile

R = os.path.expanduser("~/ctfdrill")

HINTS = {
    1: "find ~/ctfdrill -name 'flag*' -type f",
    2: "grep -rl 'flag{' ~/ctfdrill/many/",
    3: "find ~/ctfdrill -size 1337c -type f",
    4: "find ~/ctfdrill -perm -4000 -type f",
    5: "find ~/ctfdrill -mtime -1 -type f",
    6: "find ~/ctfdrill -name '.*' -type f",
    7: "grep -c ' 403 ' ~/ctfdrill/logs/access.log",
    8: "base64 -d ~/ctfdrill/enc/b64.txt",
    9: "tar tzf ~/ctfdrill/arch/archive.tar.gz ; tar xzf ... -O pkg/readme.txt",
    10: "file ~/ctfdrill/bin/mystery ; unzip -p ~/ctfdrill/bin/mystery flag.txt",
}


def first_flag(path: str) -> str:
    with open(path, "rb") as f:
        raw = f.read()
    for line in raw.split(b"\n"):
        if b"flag{" in line:
            return line.decode("utf-8", "replace").strip()
    return raw.decode("utf-8", "replace").strip()


def find_first(pred, root=R):
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = os.path.join(dirpath, name)
            if pred(p, name):
                return p
    return None


def expected():
    exp = {}
    if not os.path.isdir(R):
        sys.exit("没找到 %s —— 先在 linux/ 目录里跑 bash setup.sh" % R)

    p1 = find_first(lambda p, n: n.startswith("flag") and os.path.isfile(p))
    exp[1] = first_flag(p1) if p1 else "?"

    p2 = None
    for dirpath, _d, files in os.walk(os.path.join(R, "many")):
        for n in files:
            p = os.path.join(dirpath, n)
            with open(p, "rb") as f:
                if b"flag{" in f.read():
                    p2 = p
                    break
        if p2:
            break
    exp[2] = first_flag(p2) if p2 else "?"

    p3 = find_first(lambda p, n: os.path.getsize(p) == 1337)
    exp[3] = first_flag(p3) if p3 else "?"

    p4 = find_first(lambda p, n: os.stat(p).st_mode & 0o4000)
    exp[4] = first_flag(p4) if p4 else "?"

    now = time.time()
    p5 = find_first(lambda p, n: now - os.stat(p).st_mtime < 24 * 3600)
    exp[5] = first_flag(p5) if p5 else "?"

    p6 = find_first(lambda p, n: n.startswith("."))
    exp[6] = first_flag(p6) if p6 else "?"

    with open(os.path.join(R, "logs", "access.log"), "rb") as f:
        exp[7] = str(sum(1 for ln in f if b" 403 " in ln))

    with open(os.path.join(R, "enc", "b64.txt"), "rb") as f:
        exp[8] = base64.b64decode(f.read()).decode("utf-8", "replace").strip()

    with tarfile.open(os.path.join(R, "arch", "archive.tar.gz")) as t:
        member = [m for m in t.getmembers() if m.name.endswith("readme.txt")][0]
        exp[9] = t.extractfile(member).read().decode("utf-8", "replace").strip()

    with zipfile.ZipFile(os.path.join(R, "bin", "mystery")) as z:
        exp[10] = z.read("flag.txt").decode("utf-8", "replace").strip()

    return exp


def main() -> int:
    exp = expected()
    if "--answers" in sys.argv:
        for n in range(1, 11):
            print("T%-2d %-42s  # %s" % (n, exp[n], HINTS[n]))
        return 0

    print("Linux 命令 10 题 —— 直接输答案，回车提交（Ctrl+C 退出）\n")
    right = 0
    for n in range(1, 11):
        try:
            got = input("T%-2d 你的答案: " % n).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n中途退出")
            break
        ok = got.lower() == exp[n].lower()
        print("     %s" % ("✅ 对" if ok else "❌ 错，该用: " + HINTS[n]))
        right += ok
    print("\n得分：%d / 10" % right)
    return 0 if right == 10 else 1


if __name__ == "__main__":
    sys.exit(main())
