#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
生成 Day 11 靶场：压缩包专题（8 关，Windows 本机、纯 Python + HxD）

为什么这样设计（本机没有 7z / hashcat / john / bkcrack）：
    八关全部落在「ZIP 自己的元数据」上 —— 注释、文件名编码、flags、中央目录、CRC32。
    这些用 zipfile + struct 就能全部做完，不依赖任何 Linux 工具。

八关：
    L1  压缩包注释（EOCD 的 comment 字段）
    L2  文件名 UTF-8 字节但没置 bit11 → 显示成 cp437 乱码
    L3  伪加密（本地头 + 中央目录的 flags bit0 置 1，数据没加密）
    L4  三层嵌套（zip 里套 zip 再套 zip）
    L5  ZipCrypto 弱密码（字典 200 条，提供 wordlist.txt）
    L6  CRC32 反推（token.bin 数据被清零，CRC 留在中央目录）
    L7  zip 里的 PNG，LSB 藏 flag
    L8  综合：注释 → 弱密码 → 伪加密 → flag

⭐ 每关都是「先在内存里造出来 → 用另一套读法解回 flag → 才写盘」。
   这是 Day 6/7/8/9/10 一路的规矩：出题人先证明有解。

用法：  python build_day11_lab.py            # 输出到 out/day11/
        DAY11_DEST=/path python build_day11_lab.py   # 换输出目录
输出：  out/day11/（网页 + files/ + flags/）  +  out/Day11-答案.md
"""
import io
import itertools
import os
import struct
import sys
import tempfile
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import png_lsb  # noqa: E402  （同目录的 PNG 读取器）

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
DEST = os.environ.get("DAY11_DEST", os.path.join(HERE, "out", "day11"))
FILES = os.path.join(DEST, "files")
ANSWER_SHEET = os.path.join(os.path.dirname(DEST), "Day11-答案.md")

FLAGS = {
    1: "flag{zip_comment_is_eocd_tail}",
    2: "flag{filename_utf8_without_bit11}",
    3: "flag{pseudo_encryption_flag_bit}",
    4: "flag{three_layers_of_zip}",
    5: "flag{weak_password_from_wordlist}",
    6: "",                                    # 由 TOKEN 拼出来
    7: "flag{zip_inside_png_lsb}",
    8: "flag{comment_then_password_then_fake_crypt}",
}

TOKEN = "k3y9"                                # L6 的 4 字节 token
FLAGS[6] = "flag{%s}" % TOKEN

PASSWORD5 = "sunshine"
PASSWORD8 = "qwerty2024"

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


# ================================================================== 字典
def make_wordlist():
    """200 条常见弱口令（前 50 个词 × 4 种后缀），保证两条密码在表里。"""
    base = [
        "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
        "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
        "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
        "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
        "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
        "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
        "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
        "changeme", "welcome",
    ]
    words = []
    for w in base:
        for suf in ("", "1", "12", "2024"):
            words.append(w + suf)
    seen = set()
    out = []
    for i, w in enumerate(words):
        if w in seen:
            w = "ctf%04d" % i
        seen.add(w)
        out.append(w)
    assert len(out) == 200, len(out)

    # 两条密码放到固定位置（L8 的注释会说「第 133 条」）
    def place(idx, word):
        if word in out and out.index(word) != idx:
            j = out.index(word)
            out[j] = out[idx]
        out[idx] = word

    place(76, PASSWORD5)      # 第 77 条
    place(132, PASSWORD8)     # 第 133 条
    assert len(set(out)) == 200, "字典里有重复"
    assert out[132] == PASSWORD8 and out[76] == PASSWORD5
    return out


WORDS = make_wordlist()


# ================================================================== zip 小工具
def make_zip(entries) -> bytes:
    """普通 zip。entries: [(name, data), ...]"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


def cd_entries(data) -> list:
    """只读中央目录：返回每条的 cd 偏移 / 本地头偏移 / 名字 / 名字长度。"""
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise ValueError("找不到 EOCD")
    total = struct.unpack("<H", data[eocd + 10:eocd + 12])[0]
    off = struct.unpack("<I", data[eocd + 16:eocd + 20])[0]
    out, p = [], off
    for _ in range(total):
        if data[p:p + 4] != b"PK\x01\x02":
            raise ValueError("中央目录在偏移 %d 处断了" % p)
        namelen = struct.unpack("<H", data[p + 28:p + 30])[0]
        extralen = struct.unpack("<H", data[p + 30:p + 32])[0]
        cmtlen = struct.unpack("<H", data[p + 32:p + 34])[0]
        lfh = struct.unpack("<I", data[p + 42:p + 46])[0]
        out.append({"cd": p, "lfh": lfh,
                    "name": bytes(data[p + 46:p + 46 + namelen]),
                    "namelen": namelen})
        p += 46 + namelen + extralen + cmtlen
    return out


def set_encrypted_bit(data, on=True) -> bytes:
    """把 flags 的 bit0（加密）置 1 / 清 0 —— 本地头 +6，中央目录 +8，两处都改。"""
    d = bytearray(data)
    for e in cd_entries(d):
        for base, off in ((e["cd"], 8), (e["lfh"], 6)):
            v = struct.unpack("<H", d[base + off:base + off + 2])[0]
            v = (v | 1) if on else (v & ~1)
            d[base + off:base + off + 2] = struct.pack("<H", v)
    return bytes(d)


def rename_entry(data, new_name: bytes) -> bytes:
    """原地改文件名（长度必须一致），同时清掉 bit11 让读取方按 cp437 解释。"""
    d = bytearray(data)
    for e in cd_entries(d):
        if len(new_name) != e["namelen"]:
            raise ValueError("新名字 %d 字节 ≠ 原名 %d 字节" % (len(new_name), e["namelen"]))
        d[e["lfh"] + 30:e["lfh"] + 30 + len(new_name)] = new_name
        d[e["cd"] + 46:e["cd"] + 46 + len(new_name)] = new_name
        for base, off in ((e["cd"], 8), (e["lfh"], 6)):
            v = struct.unpack("<H", d[base + off:base + off + 2])[0]
            d[base + off:base + off + 2] = struct.pack("<H", v & ~0x800)
    return bytes(d)


# ---------------------------------------------------------------- ZipCrypto（写）
# zipfile 只能「读」传统加密，不能写 → 自己按 PKZIP 规范写一份。
def _crc_byte(crc: int, b: int) -> int:
    return (zlib.crc32(bytes([b]), crc ^ 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


class _ZipCrypto:
    def __init__(self, pwd: bytes):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in pwd:
            self._update(b)

    def _update(self, b: int) -> None:
        self.k0 = _crc_byte(self.k0, b)
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & 0xFFFFFFFF
        self.k1 = (self.k1 * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = _crc_byte(self.k2, self.k1 >> 24)

    def _stream_byte(self) -> int:
        t = (self.k2 | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for b in data:
            out.append(b ^ self._stream_byte())
            self._update(b)
        return bytes(out)


def make_zipcrypto_zip(entries, pwd: bytes, comment: bytes = b"") -> bytes:
    """entries: [(name, plain_bytes, compress_bool), ...]"""
    out, cd = bytearray(), bytearray()
    for name, plain, compress in entries:
        nb = name.encode("ascii")
        crc = zlib.crc32(plain) & 0xFFFFFFFF
        if compress:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            body, method = co.compress(plain) + co.flush(), 8
        else:
            body, method = plain, 0
        enc = _ZipCrypto(pwd)
        # 12 字节加密头：最后 1 字节 = CRC 高字节（没有数据描述符时）
        payload = enc.encrypt(bytes(11) + bytes([crc >> 24])) + enc.encrypt(body)
        flags = 0x0001
        off = len(out)
        out += b"PK\x03\x04" + struct.pack(
            "<HHHHHIIIHH", 20, flags, method, 0, 0,
            crc, len(payload), len(plain), len(nb), 0) + nb + payload
        cd += b"PK\x01\x02" + struct.pack(
            "<HHHHHHIIIHHHHHII", 20, 20, flags, method, 0, 0,
            crc, len(payload), len(plain), len(nb), 0, 0, 0, 0, 0, off) + nb
    cd_off = len(out)
    out += cd
    n = len(entries)
    out += b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, n, n, len(cd), cd_off, len(comment))
    out += comment
    return bytes(out)


# ================================================================== PNG + LSB
def noise_png(size=(320, 160), seed=20261028) -> bytes:
    """渐变 + 噪点；R 通道最低位先清 0，给 LSB 留位置。返回 PNG 字节。"""
    w, h = size
    im = Image.new("RGB", size)
    px = im.load()
    for y in range(h):
        for x in range(w):
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
            noise = (seed >> 16) & 0xFF
            px[x, y] = ((x * 255 // w) & 0xFE, noise, (y * 255 // h) & 0xFE)
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()


def lsb_embed(png_bytes: bytes, text: str) -> bytes:
    """bytes 进、bytes 出 —— 不要对同一个 BytesIO 边读边写（会追加出第二张图）。"""
    im = Image.open(io.BytesIO(png_bytes)).convert("RGB")
    w, h = im.size
    px = im.load()
    bits = "".join(format(b, "08b") for b in text.encode("utf-8"))
    if len(bits) > w * h:
        raise ValueError("图太小")
    i = 0
    for y in range(h):
        for x in range(w):
            if i >= len(bits):
                break
            r, g, b = px[x, y]
            px[x, y] = ((r & 0xFE) | int(bits[i]), g, b)
            i += 1
        if i >= len(bits):
            break
    out = io.BytesIO()
    im.save(out, format="PNG")
    return out.getvalue()


# ================================================================== 造八关（只在内存里）
def build_levels():
    lv = {}

    # L1 注释
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("readme.txt", "这不是 flag。看看这个压缩包自己说了什么。\n")
        zf.comment = ("Day11 L1 —— 压缩包也会说话。" + FLAGS[1]).encode("utf-8")
    lv[1] = {"file": "l1_comment.zip", "data": z.getvalue(),
             "info": "flag 在 EOCD 的 comment 字段里（zf.comment / 文件末尾）"}

    # L2 文件名（UTF-8 字节，bit11 = 0）
    real_name = ("秘密" + FLAGS[2] + ".txt").encode("utf-8")
    placeholder = b"x" * len(real_name)
    raw = make_zip([(placeholder.decode("ascii"), "别读内容，读名字。\n")])
    lv[2] = {"file": "l2_name.zip", "data": rename_entry(raw, real_name),
             "info": "文件名是 UTF-8 字节但没置 bit11 → 被按 cp437 解释成乱码"}

    # L3 伪加密
    raw = make_zip([("flag.txt", FLAGS[3] + "\n"),
                    ("readme.txt", "解压器要密码。可没人给过你密码。\n")])
    lv[3] = {"file": "l3_pseudo.zip", "data": set_encrypted_bit(raw, True),
             "info": "flags bit0 被置 1（本地头 + 中央目录两处），数据其实没加密"}

    # L4 三层嵌套
    core = make_zip([("flag.txt", FLAGS[4] + "\n")])
    mid = make_zip([("layer3.zip", core),
                    ("readme.txt", "还有一层。看文件头是不是 50 4B 03 04。\n")])
    outer = make_zip([("layer2.zip", mid),
                      ("readme.txt", "第 2 层在 layer2.zip 里。\n")])
    lv[4] = {"file": "l4_nested.zip", "data": outer,
             "info": "三层：外层 → layer2.zip → layer3.zip → flag.txt"}

    # L5 弱密码
    lv[5] = {"file": "l5_password.zip",
             "data": make_zipcrypto_zip([("flag.txt", (FLAGS[5] + "\n").encode(), True)],
                                        PASSWORD5.encode()),
             "info": "ZipCrypto 加密，密码是 wordlist.txt 第 77 条（%s）" % PASSWORD5}

    # L6 CRC32 反推
    note = ("本题的 flag 就是 flag{ + token.bin 的内容 + }。\n"
            "token.bin 是 4 个字符（小写字母或数字），但它的数据被清零了；\n"
            "中央目录里还留着它真实的 CRC32。\n")
    raw = bytearray(make_zip_stored([("note.txt", note), ("token.bin", TOKEN)]))
    for e in cd_entries(raw):
        if e["name"] == b"token.bin":
            off = e["lfh"] + 30 + e["namelen"]          # STORED：数据紧跟在头后面
            raw[off:off + 4] = b"\x00\x00\x00\x00"
    lv[6] = {"file": "l6_crc.zip", "data": bytes(raw),
             "info": "token.bin 数据被清零，CRC 还在中央目录 → 36^4 穷举出 4 个字符"}

    # L7 zip 里藏 PNG（LSB）
    png = lsb_embed(noise_png(), FLAGS[7])
    lv[7] = {"file": "l7_png.zip",
             "data": make_zip([("cover.png", png),
                               ("hint.txt", "解压只是第一步。图里还有一层。\n")]),
             "info": "zip 里的 cover.png 用 R 通道 LSB 藏 flag（行优先，MSB 先）"}

    # L8 综合：注释 → 弱密码 → 伪加密
    inner = set_encrypted_bit(
        make_zip([("flag.txt", FLAGS[8] + "\n"),
                  ("notes.txt", "这一层是假加密：标志位说加密，数据其实没加密。\n")]),
        True)
    comment = ("第二层看起来加密了，但数据没加密 —— 先解密这一层再清标志位。"
               "密码 = wordlist.txt 第 133 条。").encode("utf-8")
    lv[8] = {"file": "l8_final.zip",
             "data": make_zipcrypto_zip([("layer2.zip", inner, False)],
                                        PASSWORD8.encode(), comment),
             "info": "注释给密码线索 → ZipCrypto（第 133 条）→ layer2.zip 伪加密 → flag"}

    return lv


def make_zip_stored(entries) -> bytes:
    """不压缩的 zip（L6 需要「数据就是原始字节」，才好清零）。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, data in entries:
            if isinstance(data, str):
                data = data.encode("utf-8")
            z.writestr(name, data)
    return buf.getvalue()


# ================================================================== 反解验证
def _read_plain(data: bytes, name: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return z.read(name)


def _walk_zip(data: bytes) -> dict:
    """解一层，返回 {名字: 内容}；遇到 .zip 继续往下走到没有为止。"""
    out = {}
    layer = data
    for _ in range(10):
        with zipfile.ZipFile(io.BytesIO(layer)) as z:
            names = z.namelist()
            for n in names:
                out[n] = z.read(n)
            subs = [n for n in names if n.lower().endswith(".zip")]
            if not subs:
                return out
            layer = out[subs[0]]
    raise ValueError("嵌套超过 10 层")


def brute_crc(target: int, length: int = 4) -> str:
    for tup in itertools.product(ALPHABET, repeat=length):
        cand = "".join(tup)
        if zlib.crc32(cand.encode()) & 0xFFFFFFFF == target:
            return cand
    raise ValueError("CRC 反推失败（%08x）" % target)


def verify_all(lv) -> bool:
    ok = True

    def chk(n, cond, detail):
        nonlocal ok
        print(("  [ ok ] L%d  " if cond else "  [FAIL] L%d  ") % n + detail)
        if not cond:
            ok = False

    # L1
    with zipfile.ZipFile(io.BytesIO(lv[1]["data"])) as z:
        comment = z.comment
    chk(1, FLAGS[1].encode() in comment, "注释里读到 %r" % comment.decode("utf-8", "replace"))

    # L2
    with zipfile.ZipFile(io.BytesIO(lv[2]["data"])) as z:
        shown = z.namelist()[0]
        data2 = z.read(shown)
    fixed = shown.encode("cp437").decode("utf-8")
    chk(2, FLAGS[2] in fixed and len(data2) > 0,
        "显示为 %r → 还原成 %r" % (shown, fixed))

    # L3
    try:
        _read_plain(lv[3]["data"], "flag.txt")
        chk(3, False, "伪加密居然能直接读？")
    except RuntimeError:
        fixed3 = set_encrypted_bit(lv[3]["data"], False)
        got = _read_plain(fixed3, "flag.txt").decode().strip()
        chk(3, got == FLAGS[3], "两处都清 bit0 后读出 %s" % got)

    # L4
    got = _walk_zip(lv[4]["data"])
    chk(4, got.get("flag.txt", b"").decode().strip() == FLAGS[4],
        "三层走完 → %s" % got.get("flag.txt", b"").decode().strip())

    # L5
    hit = None
    for w in WORDS:
        try:
            with zipfile.ZipFile(io.BytesIO(lv[5]["data"])) as z:
                hit = z.read("flag.txt", pwd=w.encode()).decode().strip()
            break
        except (RuntimeError, zipfile.BadZipFile):
            continue
    chk(5, hit == FLAGS[5], "字典 %d 条命中 → %s" % (len(WORDS), hit))

    # L6
    with zipfile.ZipFile(io.BytesIO(lv[6]["data"])) as z:
        info = z.getinfo("token.bin")
    try:
        _read_plain(lv[6]["data"], "token.bin")
        chk(6, False, "数据清零了却还能读？")
    except zipfile.BadZipFile:
        token = brute_crc(info.CRC, 4)
        chk(6, ("flag{%s}" % token) == FLAGS[6],
            "CRC %08x → %r" % (info.CRC, token))

    # L7
    with zipfile.ZipFile(io.BytesIO(lv[7]["data"])) as z:
        png = z.read("cover.png")
    tmp = os.path.join(tempfile.gettempdir(), "_day11_l7.png")
    with open(tmp, "wb") as f:
        f.write(png)
    w7, h7, rows7 = png_lsb.read_png_rgb(tmp)
    txt = png_lsb.lsb_text_rgb(w7, h7, rows7)
    os.remove(tmp)
    chk(7, FLAGS[7] in txt, "解压 → PNG → LSB 读出 %r" % txt[:40])

    # L8
    with zipfile.ZipFile(io.BytesIO(lv[8]["data"])) as z:
        comment8 = z.comment
        inner = z.read("layer2.zip", pwd=PASSWORD8.encode())
    try:
        _read_plain(inner, "flag.txt")
        chk(8, False, "第二层伪加密居然能直接读？")
    except RuntimeError:
        got8 = _read_plain(set_encrypted_bit(inner, False), "flag.txt").decode().strip()
        chk(8, got8 == FLAGS[8] and b"133" in comment8,
            "注释 → 密码 → 清 bit0 → %s" % got8)

    return ok


# ================================================================== 页面
HEAD = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Day11 压缩包</title>
<style>
 body{background:#111;color:#ddd;font-family:Consolas,"Microsoft YaHei",monospace;padding:24px;line-height:1.75}
 a{color:#4ea1ff} h1{color:#ffcc00;font-size:22px} h2{color:#7ee787;font-size:18px}
 .box{background:#1b1b1b;border:1px solid #333;border-radius:8px;padding:16px;margin:14px 0;max-width:1000px}
 .t{color:#9aa4b2;font-size:13.5px} code{background:#000;color:#7ee787;padding:2px 6px;border-radius:4px}
 pre{background:#000;color:#7ee787;padding:12px;border-radius:6px;overflow:auto;max-height:420px;
     white-space:pre-wrap;word-break:break-all;font-size:13px}
 input[type=text]{background:#000;color:#7ee787;border:1px solid #444;padding:7px;width:520px;font-family:inherit}
 input[type=submit]{background:#2563eb;color:#fff;border:0;padding:8px 18px;border-radius:5px;cursor:pointer}
 .ok{color:#7ee787;font-weight:700} .bad{color:#ff8a80}
 .hint{background:#10202b;border-left:3px solid #4ea1ff;padding:10px 12px;border-radius:4px;color:#cfe3f5;font-size:13.5px}
 table{border-collapse:collapse;font-size:13.5px}
 td,th{border:1px solid #333;padding:5px 10px;text-align:left}
 th{background:#222;color:#7ee787}
</style>
</head>
<body>
"""

TITLES = {
    1: "压缩包注释",
    2: "文件名里的乱码",
    3: "伪加密",
    4: "三层套娃",
    5: "弱密码",
    6: "CRC32 反推",
    7: "包里那张图",
    8: "综合：注释 → 密码 → 假加密",
}

HINTS = {
    1: "这个压缩包自己会说一句话。注释不在任何文件里 —— 它在 <b>EOCD 的结尾</b>。"
       "Python 一行：<code>zipfile.ZipFile(f).comment</code>；HxD 里跳到文件最后看。",
    2: "只列目录、不解压。<b>名字显示成乱码不一定是坏了</b> —— 先想：ZIP 是按什么字符集解释文件名的？"
       "把乱码按 cp437 编码回字节、再按 UTF-8 解码，就回到真名。",
    3: "解压器说「需要密码」，但没人给过你密码。先看 flags（本地头 <code>+6</code>、中央目录 <code>+8</code>）"
       "—— 「加密」这个状态，是某一位告诉它的。注意：两处都要改。",
    4: "解一层，看一眼里面是什么。判断方法：前 4 字节是不是 <code>50 4B 03 04</code>？",
    5: "密码就在 <code>files/wordlist.txt</code>（200 条）。提示：<code>zf.read(name, pwd=...)</code> "
       "密码错会抛异常 —— 抓住它，换下一个。几百条在纯 Python 里是秒级。",
    6: "token.bin 的数据被清零了，但它的 <b>CRC32 还留在中央目录里</b>。内容只有 4 个小写字母/数字，"
       "36⁴ ≈ 168 万种，穷举。",
    7: "解压只是第一步。里面那张 PNG，按 Day 10 的 LSB 思路看（R 通道最低位，行优先，MSB 先）。",
    8: "三层：注释 → 弱密码 → 假加密。注释里写了密码是哪一条，别去爆破。",
}


def htm(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def write(rel: str, text: str, encoding: str = "utf-8") -> None:
    p = os.path.join(DEST, rel)
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(p, "w", encoding=encoding, newline="\n") as f:
        f.write(text)
    print("  写入 " + rel)


def main() -> int:
    print("生成 Day 11 靶场 → " + DEST)

    print("\n--- 内存里造八关")
    lv = build_levels()
    for n in sorted(lv):
        print("  L%d  %-16s %6d 字节  %s" % (n, lv[n]["file"], len(lv[n]["data"]), lv[n]["info"]))

    print("\n--- 反解验证（写盘前；每关都要能解回 flag）")
    if not verify_all(lv):
        print("\n验证失败，一字节都不写 ❌")
        return 1
    print("\n八关全部可解 ✅ 开始落盘\n")

    os.makedirs(FILES, exist_ok=True)
    for n in sorted(lv):
        with open(os.path.join(FILES, lv[n]["file"]), "wb") as f:
            f.write(lv[n]["data"])
        print("  写入 files/" + lv[n]["file"])

    with open(os.path.join(FILES, "wordlist.txt"), "w", encoding="utf-8", newline="\r\n") as f:
        f.write("\n".join(WORDS) + "\n")
    print("  写入 files/wordlist.txt（%d 条）" % len(WORDS))

    for n, v in FLAGS.items():
        write(os.path.join("flags", "flag%d.txt" % n), v + "\n")
    write(os.path.join("flags", ".htaccess"), "Require all denied\n", encoding="ascii")

    rows = "\n".join(
        '<p><a href="L%d.php">第 %d 关 · %s</a>　<span class="t">%s</span></p>'
        % (n, n, TITLES[n], lv[n]["file"])
        for n in sorted(lv)
    )

    write("index.php", HEAD + """<h1>Day 11 · 压缩包专题（8 关）</h1>
<div class="box">
<p>规则：每关给你一个<b>压缩包</b>。flag 藏在它的<b>元数据</b>里（注释 / 文件名 / flags / 中央目录 / CRC），
不是靠猜密码猜出来的。</p>
<p>⚠️ 顺序：<b>先做完 <a href="zip-basics.html">背景题（16 题）</a></b>，再来打这八关。</p>
<p class="t">⚠️ 不需要 7z / hashcat / john —— 本机也没有。</p>
</div>

<div class="box">
<h2>八关</h2>
%s
</div>

<div class="box">
<h2>工具</h2>
<table>
<tr><th>干什么</th><th>用什么</th></tr>
<tr><td>看字节 / 改字节</td><td><code>HxD</code>（Windows 免费十六进制编辑器；Ctrl+G 跳偏移、Ctrl+E 编辑）</td></tr>
<tr><td>列目录 / 读注释 / 读 CRC</td><td>Python：<code>zipfile.ZipFile(f).infolist()</code> / <code>.comment</code></td></tr>
<tr><td>改 flags / 改文件名</td><td><code>struct</code> 定位偏移后直接改字节（本地头 +6，中央目录 +8）</td></tr>
<tr><td>爆破密码</td><td><code>zf.read(name, pwd=...)</code> 循环，错了抛异常</td></tr>
<tr><td>CRC 反推</td><td><code>zlib.crc32</code> 穷举</td></tr>
</table>
<p class="t">常用一行：</p>
<pre>import zipfile
z = zipfile.ZipFile(r"文件.zip")
print(z.comment)                       # 注释
for i in z.infolist():
    print(i.filename, i.flag_bits, hex(i.CRC), i.file_size)</pre>
</div>

<div class="box">
<h2>交 flag 判分</h2>
<p><a href="check.php">→ 打开判分页</a>（8 个 flag 逐个交，交对会告诉你是第几关）</p>
</div>
</body></html>
""" % rows)

    for n in sorted(lv):
        write("L%d.php" % n, HEAD + """<?php error_reporting(0); ?>
<h1>Day 11 · 第 %d 关 · %s</h1>
<div class="box">
<p class="hint"><b>提示：</b>%s</p>
</div>
<div class="box">
<h2>文件</h2>
<p><a href="files/%s" download>⬇ 下载 %s</a>　<span class="t">别的关卡也可能用到 files/wordlist.txt</span></p>
</div>
<div class="box">
<h2>交答案</h2>
<form method="post">
  <input type="text" name="answer" placeholder="flag{...}" value="<?=htmlspecialchars(isset($_POST['answer'])?trim($_POST['answer']):'', ENT_QUOTES)?>">
  <input type="submit" value="提交">
</form>
<?php
if (isset($_POST['answer'])) {
    $mine = trim($_POST['answer']);
    $real = trim(@file_get_contents(__DIR__ . '/flags/flag%d.txt'));
    if ($mine === $real) {
        echo '<p class="ok">✅ 对了！flag: ' . htmlspecialchars($real) . '</p>';
    } elseif ($mine === '') {
        echo '<p class="bad">别交空的 —— 先把压缩包拆开。</p>';
    } else {
        echo '<p class="bad">❌ 不对。先想：这关该读的是元数据哪一段？</p>';
    }
}
?>
</div>
<div class="box"><p><a href="index.php">← 回关卡列表</a> ｜ <a href="check.php">去判分</a> ｜
<a href="zip-basics.html">背景题</a></p></div>
</body></html>
""" % (n, TITLES[n], HINTS[n], lv[n]["file"], lv[n]["file"], n))

    write("check.php", HEAD + """<?php
$mine = null; $result = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['flag'])) {
    $mine = trim($_POST['flag']);
    for ($n = 1; $n <= 8; $n++) {
        $f = @file_get_contents(__DIR__ . '/flags/flag' . $n . '.txt');
        if ($f !== false && trim($f) === $mine) { $result = $n; break; }
    }
}
?>
<h1>Day 11 · 交 flag 判分</h1>
<div class="box">
<form method="post">
  你的 flag: <input type="text" name="flag" value="<?=htmlspecialchars((string)$mine, ENT_QUOTES)?>" placeholder="flag{...}">
  <input type="submit" value="提交">
</form>
<?php if ($mine !== null): ?>
  <?php if ($result): ?><p class="ok">✅ 正确！这是【第 <?=$result?> 关】的 flag。</p>
  <?php else: ?><p class="bad">❌ 不对（注意大小写和多余空格）。</p><?php endif; ?>
<?php endif; ?>
</div>
<div class="box"><p><a href="index.php">← 回关卡列表</a></p></div>
</body></html>
""")

    lines = [
        "# Day 11 · 压缩包（8 关）· 答案与原理",
        "",
        "> ⚠️ **先自己做完八关再看这份** ✅",
        "> 生成器：`scripts\\ctf\\build_day11_lab.py`（内存里造 + 反解验证，全过才落盘）",
        "> 靶场入口：`http://127.0.0.1/day11/`　背景题：`labs\\js\\zip-basics.html`",
        "",
    ]
    for n in sorted(lv):
        lines += [
            "## 第 %d 关 · %s" % (n, TITLES[n]),
            "",
            "**文件**：`files/%s`" % lv[n]["file"],
            "",
            "**手法**：%s" % lv[n]["info"],
            "",
            "**答案**：`%s`" % FLAGS[n],
            "",
            "---",
            "",
        ]
    with open(ANSWER_SHEET, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    print("  写入（只在工作区）" + ANSWER_SHEET)

    print("\n完成 ✅  入口： http://127.0.0.1/day11/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
