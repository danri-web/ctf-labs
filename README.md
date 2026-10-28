# ctf-labs

> 自建 CTF 练习靶场合集：**Web / Linux / ZIP**。纯 Python 标准库实现，离线可跑。
> 每个靶场都遵守同一条规矩：**先证明有解，再交给做题的人**。

⚠️ **免责声明**：本仓库的代码**故意包含安全漏洞**，仅用于本地学习与教学。
**禁止部署到公网或任何生产环境。** 使用即表示你明白这一点。

---

## 目录

| 目录 | 内容 | 依赖 |
|---|---|---|
| `web/` | 一个故意留了 5 个洞的小站（SQLi / 路径穿越 / 命令注入 / 弱口令 / robots 泄露） | Python 3 标准库 |
| `linux/` | Linux 命令限时练 10 题（find / grep / 权限 / 时间 / 归档 / 编码） | bash + Python 3 |
| `zip/` | ZIP 压缩包专题 8 关 + 16 题背景页（注释 / 文件名编码 / 伪加密 / 嵌套 / 弱口令 / CRC32 / LSB） | Python 3（生成器需 Pillow） |
| `docs/` | 两张比赛用速查表：Linux 命令、Web 简单题 | — |

---

## 快速开始

### web

```bash
cd web
python3 vulnweb.py          # 默认 8000 端口
# 浏览器打开 http://127.0.0.1:8000/
```

5 关的题面在 `web/questions.md`，交答案用 `python3 check.py`。

### linux

```bash
cd linux
bash setup.sh               # 在 ~/ctfdrill 下布置 10 题
cat questions.md            # 看题
python3 check.py            # 判分（答案从现场文件现算）
```

### zip

```bash
cd zip
python3 build_day11_lab.py  # 生成到 zip/out/day11（每关写盘前先反解验证）
python3 -m http.server 8080 -d out/day11
```

- 背景题：`out/day11/zip-basics.html`（纯静态，直接打开）
- 八关的样本在 `out/day11/files/`，**不解网页也能做**（自己用 Python/HxD 拆）
- 关卡页是 `.php`，需要 PHP 环境；只做题不需要
- 回归测试（需要先把 `out/day11` 架到 web 根）：

```bash
DAY11_BASE=http://127.0.0.1/day11 python3 verify_day11.py
```

---

## 设计原则

1. **先证明有解**：`build_*.py` 在写盘前用另一套读法把每一关解一遍，解不开就不落盘。
2. **判分不写死答案**：`check.py` 从现场文件/日志重新计算期望值 —— 改题目不会让判分失效。
3. **不依赖重型工具**：不需要 Kali、binwalk、hashcat；Windows 上 HxD + Python 就够。

## 许可

MIT，见 [LICENSE](LICENSE)。
