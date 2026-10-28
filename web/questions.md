# Web 热身 · 5 关（限时 40 分钟）

## 启动（在 Linux 里）

```bash
cd web
python3 vulnweb.py
```

然后浏览器开 `http://127.0.0.1:8000/`。
Ctrl+C 停止。

---

## 规则

- **先黑盒**：只从浏览器/curl 打，不要一上来读 `vulnweb.py`。
- 固定顺序：**看首页 → 看 robots.txt → 看源码/备份 → 动每个参数**。
- 5 个 flag 分别是 5 种不同的洞，每个洞一个。
- 卡住超过 6 分钟就换下一关，回头再来。

## 5 关

| 关 | 入口 | 提示 |
|---|---|---|
| L1 | `/login` | 用户名里加一个单引号，看报错；再想想登录 SQL 长什么样 |
| L2 | `/download?file=readme.txt` | `file` 参数能写 `../` 吗？flag 不在 `files/` 里 |
| L3 | `/ping?ip=127.0.0.1` | 命令拼接符：`;` `|` `&&`；想想服务器上 flag 在哪 |
| L4 | `/admin` | 弱口令。先试最常见的那几个，别急着爆破 |
| L5 | `/robots.txt` | 它告诉你哪个目录不该看 —— 那就去看 |

## 交答案

```bash
python3 check.py          # 逐关输入 flag
python3 check.py --answers   # 做完再看
```
