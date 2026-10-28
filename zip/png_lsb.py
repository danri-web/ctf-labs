#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""png_lsb.py —— 纯标准库读 PNG 像素 + 取 R 通道 LSB（Day 11 的 L7 用它自检）。

只支持 8 位、RGB（color type 2）、非隔行 —— 正好覆盖本仓库自己生成的图。
独立实现（不依赖 Pillow），所以它能和出题时的 Pillow 互证。
"""
import struct
import zlib


def read_png_rgb(path: str):
    """返回 (width, height, rows)，rows 是每行 RGB 字节串。"""
    with open(path, "rb") as f:
        data = f.read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("不是 PNG")
    pos, idat = 8, b""
    w = h = None
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        if ctype == b"IHDR":
            w, h, depth, color, _comp, _filt, interlace = struct.unpack(">IIBBBBB", body)
            if depth != 8 or color != 2 or interlace != 0:
                raise ValueError("只支持 8 位 RGB 非隔行 PNG")
        elif ctype == b"IDAT":
            idat += body
        elif ctype == b"IEND":
            break
        pos += 12 + length

    raw = zlib.decompress(idat)
    stride = w * 3
    rows, prev, p = [], bytearray(stride), 0
    for _y in range(h):
        ftype = raw[p]
        p += 1
        line = bytearray(raw[p:p + stride])
        p += stride
        if ftype == 1:                      # Sub
            for i in range(3, stride):
                line[i] = (line[i] + line[i - 3]) & 0xFF
        elif ftype == 2:                    # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:                    # Average
            for i in range(stride):
                a = line[i - 3] if i >= 3 else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:                    # Paeth
            for i in range(stride):
                a = line[i - 3] if i >= 3 else 0
                b = prev[i]
                c = prev[i - 3] if i >= 3 else 0
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pred) & 0xFF
        rows.append(bytes(line))
        prev = line
    return w, h, rows


def lsb_text_rgb(w: int, h: int, rows, limit: int = 4000) -> str:
    """按行优先取每像素 R 通道最低位，每 8 bit 一个字节（MSB 先）。"""
    bits = []
    for row in rows:
        for x in range(w):
            bits.append(str(row[3 * x] & 1))
            if len(bits) >= limit:
                break
        if len(bits) >= limit:
            break
    raw = bytes(int("".join(bits[i:i + 8]), 2) for i in range(0, len(bits) - 7, 8))
    return raw.decode("utf-8", "replace")
