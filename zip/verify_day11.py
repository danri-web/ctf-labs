#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Day 11 靶场回归测试：真走 HTTP 下载八个压缩包 → 自己解析 → 解出 flag → 提交。

独立性说明（这是这个文件存在的意义）：
    · EOCD / 中央目录的定位与字段解析在这里【手工重写一遍】（从尾巴扫签名），
      不复用生成器的 cd_entries()。
    · ZipCrypto 解密也在这里【按 PKZIP 规范重新实现】一份（表驱动、从密文反推明文），
      再和标准库 zipfile 的结果互相印证 —— 两套实现都对，才算过。
    · 只有读 PNG 像素复用同目录的 png_lsb.py：它是纯标准库实现，
      和出题时用的 Pillow 是两套代码，正好互证。

用法： python scripts\\ctf\\verify_day11.py
"""
import io
import itertools
import os
import re
import struct
import sys
import tempfile
import zipfile
import zlib

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import png_lsb  # noqa: E402

BASE = os.environ.get("DAY11_BASE", "http://127.0.0.1/day11")
TMP = os.path.join(tempfile.gettempdir(), "_day11_verify.png")
ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
problems = []


def say(tag, msg):
    print("[%s] %s" % (tag, msg))


def bad(msg):
    problems.append(msg)
    say("FAIL", msg)


# ================================================================== 手工解析 ZIP
def find_eocd(data: bytes) -> dict:
    """从文件尾往前扫 50 4B 05 06，且 eocd + 22 + 注释长度 == 文件长度。"""
    sig = b"PK\x05\x06"
    for pos in range(len(data) - 22, max(-1, len(data) - 65558), -1):
        if data[pos:pos + 4] == sig:
            cmtlen = struct.unpack("<H", data[pos + 20:pos + 22])[0]
            if pos + 22 + cmtlen == len(data):
                return {
                    "pos": pos,
                    "total": struct.unpack("<H", data[pos + 10:pos + 12])[0],
                    "cd_size": struct.unpack("<I", data[pos + 12:pos + 16])[0],
                    "cd_off": struct.unpack("<I", data[pos + 16:pos + 20])[0],
                    "comment": data[pos + 22:pos + 22 + cmtlen],
                }
    raise ValueError("找不到合法的 EOCD")


def parse_central(data: bytes) -> list:
    """只读中央目录。字段偏移和生成器无关（按规范硬编码）。"""
    eocd = find_eocd(data)
    out, pos = [], eocd["cd_off"]
    for _ in range(eocd["total"]):
        if data[pos:pos + 4] != b"PK\x01\x02":
            raise ValueError("中央目录签名不对 @%d" % pos)
        flags = struct.unpack("<H", data[pos + 8:pos + 10])[0]
        method = struct.unpack("<H", data[pos + 10:pos + 12])[0]
        crc = struct.unpack("<I", data[pos + 16:pos + 20])[0]
        csize = struct.unpack("<I", data[pos + 20:pos + 24])[0]
        usize = struct.unpack("<I", data[pos + 24:pos + 28])[0]
        nlen = struct.unpack("<H", data[pos + 28:pos + 30])[0]
        elen = struct.unpack("<H", data[pos + 30:pos + 32])[0]
        clen = struct.unpack("<H", data[pos + 32:pos + 34])[0]
        lfh = struct.unpack("<I", data[pos + 42:pos + 46])[0]
        out.append({"name": data[pos + 46:pos + 46 + nlen], "flags": flags,
                    "method": method, "crc": crc, "csize": csize, "usize": usize,
                    "lfh": lfh})
        pos += 46 + nlen + elen + clen
    return out


def raw_data_offset(data: bytes, ent: dict) -> tuple:
    """本地头 → (数据起始偏移, 本地头里的 flags)。"""
    if data[ent["lfh"]:ent["lfh"] + 4] != b"PK\x03\x04":
        raise ValueError("本地头签名不对 @%d" % ent["lfh"])
    lflags = struct.unpack("<H", data[ent["lfh"] + 6:ent["lfh"] + 8])[0]
    nlen = struct.unpack("<H", data[ent["lfh"] + 26:ent["lfh"] + 28])[0]
    elen = struct.unpack("<H", data[ent["lfh"] + 28:ent["lfh"] + 30])[0]
    return ent["lfh"] + 30 + nlen + elen, lflags


def clear_bit0(data: bytes) -> bytes:
    """手工清加密标志：本地头 +6、中央目录条目 +8，一个都不漏。"""
    d = bytearray(data)
    eocd = find_eocd(d)
    pos = eocd["cd_off"]
    for _ in range(eocd["total"]):
        lfh = struct.unpack("<I", d[pos + 42:pos + 46])[0]
        for base, off in ((pos, 8), (lfh, 6)):
            v = struct.unpack("<H", d[base + off:base + off + 2])[0]
            d[base + off:base + off + 2] = struct.pack("<H", v & ~1)
        nlen = struct.unpack("<H", d[pos + 28:pos + 30])[0]
        elen = struct.unpack("<H", d[pos + 30:pos + 32])[0]
        clen = struct.unpack("<H", d[pos + 32:pos + 34])[0]
        pos += 46 + nlen + elen + clen
    return bytes(d)


# ================================================================== 独立 ZipCrypto 解密
def _crc_tab_byte(crc: int, b: int) -> int:
    return (zlib.crc32(bytes([b]), crc ^ 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


class ZipCryptoDec:
    """按 PKZIP 规范解密：先解 12 字节头，校验最后 1 字节，再解正文。"""

    def __init__(self, pwd: bytes):
        self.k = [0x12345678, 0x23456789, 0x34567890]
        for ch in pwd:
            self._upd(ch)

    def _upd(self, b: int) -> None:
        self.k[0] = _crc_tab_byte(self.k[0], b)
        self.k[1] = ((self.k[1] + (self.k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.k[2] = _crc_tab_byte(self.k[2], self.k[1] >> 24)

    def _stream(self) -> int:
        t = (self.k[2] | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def decrypt(self, blob: bytes) -> bytes:
        """返回完整明文（含 12 字节加密头；调用方自己切掉）。"""
        out = bytearray()
        for c in blob:
            p = c ^ self._stream()
            out.append(p)
            self._upd(p)
        return bytes(out)


def zipcrypto_extract(data: bytes, ent: dict, pwd: bytes) -> bytes:
    off, _lflags = raw_data_offset(data, ent)
    blob = data[off:off + ent["csize"]]
    body = ZipCryptoDec(pwd).decrypt(blob)[12:]
    if ent["method"] == 8:
        d = zlib.decompressobj(-15)
        return d.decompress(body) + d.flush()
    return body


def check_header_byte(data: bytes, ent: dict, pwd: bytes) -> bool:
    """加密头最后 1 字节应等于 CRC 高字节 —— 这既是解密校验，也是爆破的判据。"""
    off, _ = raw_data_offset(data, ent)
    plain = ZipCryptoDec(pwd).decrypt(data[off:off + 12])
    return plain[11] == (ent["crc"] >> 24) & 0xFF


# ================================================================== 解
def brute_crc(target: int, length: int = 4) -> str:
    for tup in itertools.product(ALPHABET, repeat=length):
        cand = "".join(tup)
        if zlib.crc32(cand.encode()) & 0xFFFFFFFF == target:
            return cand
    raise ValueError("CRC 反推失败（%08x）" % target)


def flag_of(text: str):
    m = re.search(r"flag\{[a-z0-9_]+\}", text)
    return m.group(0) if m else None


def main() -> int:
    s = requests.Session()
    found = {}

    r = s.get(BASE + "/", timeout=10)
    if r.status_code != 200 or "压缩包" not in r.content.decode("utf-8","replace"):
        bad("首页异常 HTTP %d" % r.status_code)
    else:
        say(" ok ", "首页 200 + 中文正常")

    r = s.get(BASE + "/zip-basics.html", timeout=10)
    if r.status_code != 200 or "背景题" not in r.content.decode("utf-8","replace"):
        bad("背景题页异常 HTTP %d" % r.status_code)
    else:
        say(" ok ", "背景题页 200")

    r = s.get(BASE + "/flags/flag1.txt", timeout=10)
    if r.status_code != 403:
        bad("flags/flag1.txt 可被直接访问（HTTP %d）" % r.status_code)
    else:
        say(" ok ", "flags 目录 403")

    # 字典：200 条，第 133 条要和 L8 注释对得上（关系断言，不是快照）
    wl = s.get(BASE + "/files/wordlist.txt", timeout=10)
    words = wl.content.decode("utf-8","replace").split()
    if len(words) != 200:
        bad("wordlist 不是 200 条（%d）" % len(words))
    else:
        say(" ok ", "wordlist 200 条")

    def get(name: str) -> bytes:
        rr = s.get(BASE + "/files/" + name, timeout=15)
        if rr.status_code != 200:
            raise AssertionError("下载 %s 失败：HTTP %d" % (name, rr.status_code))
        return rr.content

    # ---------------- L1 注释
    d1 = get("l1_comment.zip")
    e1 = find_eocd(d1)
    c1 = e1["comment"].decode("utf-8", "replace")
    found[1] = flag_of(c1)
    if found[1]:
        say(" ok ", "L1 EOCD 注释（%d 字节）→ %s" % (len(e1["comment"]), found[1]))
    else:
        bad("L1 注释里没有 flag：%r" % c1[:60])

    # ---------------- L2 文件名
    d2 = get("l2_name.zip")
    ents2 = parse_central(d2)
    name2 = ents2[0]["name"].decode("cp437")
    fixed2 = name2.encode("cp437").decode("utf-8", "replace")
    found[2] = flag_of(fixed2)
    if found[2] and not (ents2[0]["flags"] & 0x800):
        say(" ok ", "L2 bit11=0，%r → %r" % (name2, fixed2))
    else:
        bad("L2 文件名还原失败：%r" % fixed2)

    # ---------------- L3 伪加密
    d3 = get("l3_pseudo.zip")
    ents3 = parse_central(d3)
    ent3 = [e for e in ents3 if e["name"] == b"flag.txt"][0]
    off3, lflags3 = raw_data_offset(d3, ent3)
    if not (ent3["flags"] & 1 and lflags3 & 1):
        bad("L3 加密标志没同时出现在两处（cd=%04x lfh=%04x）" % (ent3["flags"], lflags3))
    else:
        say(" ok ", "L3 两处 bit0 都置了（cd=%04x lfh=%04x）" % (ent3["flags"], lflags3))
    try:
        with zipfile.ZipFile(io.BytesIO(d3)) as z:
            z.read("flag.txt")
        bad("L3 伪加密居然能直接读")
    except RuntimeError:
        pass
    d3c = clear_bit0(d3)
    with zipfile.ZipFile(io.BytesIO(d3c)) as z:
        body3 = z.read("flag.txt").decode()
    found[3] = flag_of(body3)
    if found[3]:
        say(" ok ", "L3 手工清两处 → %s" % found[3])
    else:
        bad("L3 清标志后没读出 flag")

    # ---------------- L4 三层嵌套
    d4 = get("l4_nested.zip")
    layers, cur = 0, d4
    while True:
        with zipfile.ZipFile(io.BytesIO(cur)) as z:
            names = z.namelist()
            subs = [n for n in names if n.endswith(".zip")]
            if not subs:
                found[4] = flag_of(z.read("flag.txt").decode())
                break
            cur = z.read(subs[0])
        layers += 1
        if layers > 5:
            raise AssertionError("嵌套太深")
    if found[4] and layers == 2:
        say(" ok ", "L4 解了 %d 层 → %s" % (layers + 1, found[4]))
    else:
        bad("L4 层数/flag 不对：layers=%d flag=%r" % (layers, found[4]))

    # ---------------- L5 弱密码（自己解密 + zipfile 互证）
    d5 = get("l5_password.zip")
    ent5 = parse_central(d5)[0]
    hit5 = None
    for idx, w in enumerate(words, 1):
        if check_header_byte(d5, ent5, w.encode()):
            hit5 = (idx, w)
            break
    if not hit5:
        bad("L5 字典里没有一个密码能过校验字节")
    else:
        idx5, pw5 = hit5
        plain5 = zipcrypto_extract(d5, ent5, pw5.encode()).decode()
        with zipfile.ZipFile(io.BytesIO(d5)) as z:          # 第二套实现互证
            ref5 = z.read("flag.txt", pwd=pw5.encode()).decode()
        found[5] = flag_of(plain5)
        if found[5] and plain5 == ref5:
            say(" ok ", "L5 第 %d 条 %r 解出 %s（与 zipfile 一致）" % (idx5, pw5, found[5]))
        else:
            bad("L5 自己解和 zipfile 不一致")

    # ---------------- L6 CRC 反推
    d6 = get("l6_crc.zip")
    ent6 = [e for e in parse_central(d6) if e["name"] == b"token.bin"][0]
    off6, _ = raw_data_offset(d6, ent6)
    disk6 = d6[off6:off6 + ent6["usize"]]
    if disk6 != b"\x00" * 4 or ent6["usize"] != 4:
        bad("L6 token.bin 不是 4 字节全零（%r）" % disk6)
    else:
        say(" ok ", "L6 盘上是 4 个零字节，中央目录 CRC=%08x" % ent6["crc"])
    try:
        with zipfile.ZipFile(io.BytesIO(d6)) as z:
            z.read("token.bin")
        bad("L6 数据清零了却还能读")
    except zipfile.BadZipFile:
        token6 = brute_crc(ent6["crc"])
        found[6] = "flag{%s}" % token6
        say(" ok ", "L6 CRC → token %r" % token6)

    # ---------------- L7 包中 PNG
    with zipfile.ZipFile(io.BytesIO(get("l7_png.zip"))) as z:
        png = z.read("cover.png")
    with open(TMP, "wb") as f:
        f.write(png)
    w7, h7, rows7 = png_lsb.read_png_rgb(TMP)
    txt7 = png_lsb.lsb_text_rgb(w7, h7, rows7)
    found[7] = flag_of(txt7)
    if found[7]:
        say(" ok ", "L7 zip → PNG → LSB %s" % found[7])
    else:
        bad("L7 LSB 没解出 flag：%r" % txt7[:40])

    # ---------------- L8 综合
    d8 = get("l8_final.zip")
    c8 = find_eocd(d8)["comment"].decode("utf-8", "replace")
    if "133" not in c8:
        bad("L8 注释里没提第 133 条：%r" % c8)
    ent8 = parse_central(d8)[0]
    pw8 = words[132]
    if not check_header_byte(d8, ent8, pw8.encode()):
        bad("L8 第 133 条 %r 解不开" % pw8)
    inner = zipcrypto_extract(d8, ent8, pw8.encode())
    with zipfile.ZipFile(io.BytesIO(inner)) as z:
        names8 = z.namelist()
        try:
            z.read("flag.txt")
            bad("L8 第二层伪加密居然能直接读")
        except RuntimeError:
            pass
    inner_c = clear_bit0(inner)
    with zipfile.ZipFile(io.BytesIO(inner_c)) as z:
        found[8] = flag_of(z.read("flag.txt").decode())
    if found[8] and ent8["name"] == b"layer2.zip" and "flag.txt" in names8:
        say(" ok ", "L8 注释 → 第 133 条 → 清假加密 → %s" % found[8])
    else:
        bad("L8 链路断了：outer=%r inner=%r flag=%r" % (ent8["name"], names8, found[8]))

    if os.path.exists(TMP):
        os.remove(TMP)

    # ---------------- 提交（八关 + check.php）
    for n in range(1, 9):
        if not found.get(n):
            bad("L%d 没解出 flag，跳过提交" % n)
            continue
        rr = s.post(BASE + "/L%d.php" % n, data={"answer": found[n]}, timeout=10)
        if "对了" not in rr.content.decode("utf-8","replace"):
            bad("L%d 正确答案没被判对：%s" % (n, found[n]))
        rc = s.post(BASE + "/check.php", data={"flag": found[n]}, timeout=10)
        if ("第 %d 关" % n) not in rc.content.decode("utf-8","replace"):
            bad("check.php 没认出第 %d 关" % n)

    print("")
    if problems:
        print("RESULT: %d 个问题 ❌" % len(problems))
        return 1
    print("RESULT: 全过 ✅  八关都能从 HTTP 下载 → 自己解析 → 判对")
    return 0


if __name__ == "__main__":
    sys.exit(main())
