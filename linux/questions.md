# Linux 命令 · 10 题限时（40 分钟）

在 Linux 里：

```bash
bash setup.sh          # 布置环境（在 linux/ 目录里）
```

全部题目都在 `~/ctfdrill` 下。**先别看 setup.sh 的内容**，也别用 `ls -R` 人眼扫 —— 这练的就是「不知道在哪时用什么命令」。

做完跑 `python3 check.py` 判分；答错的题会告诉你该用哪条命令。

---

## 题目

**T1** 找一个**文件名以 flag 开头**的文件，读出里面的 flag。
（考：按名字找）

**T2** `~/ctfdrill/many/` 下有 120 个文件，只有一个里面有 `flag{`。
把它找出来。
（考：按内容找）

**T3** 找出一个**大小正好 1337 字节**的文件，读出 flag。
（考：按大小找）

**T4** 找出一个带 **SUID 位**的文件，读出 flag。
（考：按权限找）

**T5** 找出一个 **24 小时内被修改过**的文件，读出 flag。
（考：按时间找）

**T6** 找一个**隐藏文件**（文件名以点开头），读出 flag。
（考：隐藏文件也是文件）

**T7** `~/ctfdrill/logs/access.log` 里，**状态码 403 出现了几次**？
（答案是数字，不是 flag。考：计数）

**T8** `~/ctfdrill/enc/b64.txt` 里的内容是编码过的，解出来。
（考：base64）

**T9** `~/ctfdrill/arch/archive.tar.gz`：**先不解压**，看包里有什么；再把 flag 取出来。
（考：tar 列表 + 解压）

**T10** `~/ctfdrill/bin/mystery` 没有扩展名：判断它到底是什么文件，再取出里面的 flag。
（考：file + 按真实类型处理）

---

## 判分

```bash
python3 check.py            # 逐题输入答案
python3 check.py --answers  # 做完再看标准答案和命令
```
