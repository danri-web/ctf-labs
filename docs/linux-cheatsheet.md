# Linux 命令速查（比赛版）

> 用法：先看「10 秒定位」，再跳小节。每条后面那句是**什么时候用**，不是解释。
> 比赛里 `man` / `--help` 永远比背参数快。

---

## 0. 10 秒定位

| 症状 | 第一条命令 |
|---|---|
| 不知道文件在哪 | `find / -name "*flag*" 2>/dev/null` |
| 不知道内容在哪 | `grep -rn "flag{" /path 2>/dev/null` |
| 不知道文件是什么 | `file x`　然后 `xxd x \| head` |
| 不知道谁在监听 | `ss -lntp` |
| 不知道能提权到哪 | `sudo -l`　`find / -perm -4000 -type f 2>/dev/null` |
| 不知道最近改了什么 | `find / -mmin -30 -type f 2>/dev/null` |
| 归档/压缩 | `tar tzf x`（先看再解）`unzip -l x` |
| 编码 | `base64 -d`　`xxd -r -p` |

---

## 1. 找文件（find）

```bash
find / -name "flag*" -type f 2>/dev/null      # 按名字（2>/dev/null 扔掉权限报错）
find . -iname "*.txt"                          # 不分大小写
find . -size 1337c                             # 正好 1337 字节（c=字节，k/M=KB/MB）
find . -size +1M -size -5M                     # 区间
find . -mmin -10                               # 10 分钟内改过（-mtime -1 = 1 天内）
find . -perm -4000 -type f                     # SUID
find . -perm -0002                             # 任何人可写
find . -user root -group root
find . -maxdepth 2 -name "*.log"
```
批量处理（找到就执行）：

```bash
find . -name "*.txt" -exec grep -l "flag" {} \;
find . -name "*.txt" -print0 | xargs -0 grep -l flag
```

## 2. 搜内容（grep）

```bash
grep -rn "flag{" .                 # -r 递归 -n 行号（最常用的一条）
grep -rn --include="*.php" "pass" .
grep -c " 403 " access.log         # 计数
grep -v "^#" file                  # 排除注释
grep -o "flag{[^}]*}" file         # 只输出匹配到的部分
zgrep "flag" x.gz                  # 压缩包里搜
strings -a file | grep -i flag     # 二进制里搜
```

## 3. 看文件

```bash
file x; stat x; ls -l x
head -20 x; tail -20 x
less x        # /搜索  n下一个  q退出
xxd x | head -40                   # 十六进制
xxd -r -p hex.txt > out.bin        # 十六进制转二进制
od -c x | head                     # 看不可见字符
cat -A x                           # ^I=Tab  $=换行
```

## 4. 权限 / 用户 / 提权入口

```bash
id; whoami; groups
ls -l        # rwx rwx rwx = 属主 组 其他
chmod 755 x; chmod u+s x; chmod 000 x
sudo -l                            # 能 sudo 什么（提权第一问）
cat /etc/passwd | grep sh          # 哪些用户能登录
find / -perm -u+s -type f 2>/dev/null    # SUID
getcap -r / 2>/dev/null                  # capabilities
crontab -l; cat /etc/crontab; ls /etc/cron.d/   # 计划任务
systemctl list-timers
```

## 5. 进程 / 端口

```bash
ps aux | grep -v grep | grep python
ss -lntp                    # 监听端口（进程名要 root 才显示）
ss -antp | grep ESTAB       # 已建立连接
lsof -i :80
kill -9 PID
```

## 6. 网络

```bash
ip a; ip r
curl -i http://ip/                          # 带响应头
curl -X POST -d "a=1&b=2" http://ip/
curl -o out.bin http://ip/file
curl -k -L -b "k=v" http://ip/
wget -r -np http://ip/                      # 递归下载整站
nc -lvnp 4444                               # 监听（反弹 shell 用）
nc ip 1234                                  # 连接（pwn 题就是这个）
ssh user@ip; scp file user@ip:/tmp/
```

## 7. 归档 / 压缩

```bash
tar tzf x.tar.gz              # 先看内容，不解压
tar xzf x.tar.gz              # 解压
tar czf out.tar.gz dir/
unzip -l x.zip                # 看列表
unzip x.zip -d dst
zip -r out.zip dir/
7z l x.7z; 7z x x.7z
```
不知道格式就先 `file`；看有没有嵌套用 `binwalk x`。

## 8. 编码 / 文本处理

```bash
base64 -d <<< "xxx"; base64 -w0 file
xxd -r -p
rev; tr 'A-Z' 'a-z'
cut -d: -f1 /etc/passwd
sort file | uniq -c | sort -rn | head      # 词频 Top
awk '{print $1}' file | sort -u
sed 's/a/b/g' file
printf '%d\n' 0x41                          # 十六进制转十进制
```

## 9. 日志

```bash
/var/log/auth.log        # 登录（Debian/Kali）
/var/log/syslog
/var/log/apache2/access.log
last; lastb; who; w
journalctl -u ssh --since "1 hour ago"
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
```

## 10. 救命操作

- `Tab` 补全；`↑` 历史；`Ctrl+C` 中断；`Ctrl+Z` 挂起后 `fg`
- vim：`i` 插入，`Esc`，`:wq` 保存退出，`:q!` 强退，`/x` 搜，`dd` 删行
- `history | grep xxx` 找回刚才那条
- 命令找不到：`which cmd`、`apt list --installed | grep cmd`

---

## 11. 比赛题型对照（看到题先想这个）

| 题面关键词 | 先试 |
|---|---|
| 「找 flag 文件」 | `find / -name "*flag*"` |
| 「内容藏在一堆文件里」 | `grep -rn` |
| 「大小/时间异常」 | `find -size` / `-mmin` |
| 「提权」 | `sudo -l` → SUID → cron → 可写配置 |
| 「日志分析」 | `grep + awk + sort | uniq -c` |
| 「连服务」 | `nc ip port` |
| 「编码/乱码」 | `file` → `base64 -d` → `xxd -r -p` |
