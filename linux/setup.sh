#!/usr/bin/env bash
# Linux 命令限时练 —— 布置环境（在 Kali 里跑，不需要 sudo）
# 用法：bash setup.sh
# 说明：10 道题全部在 ~/ctfdrill 下；答案用 check.py 判。
set -eu
R="$HOME/ctfdrill"
rm -rf "$R"
mkdir -p "$R/deep/a/b/c" "$R/many" "$R/perm" "$R/logs" "$R/enc" "$R/arch" "$R/bin"

# T1 按文件名找
printf 'flag{find_by_name_7a1c}\n' > "$R/deep/a/b/c/flag1.txt"

# T2 在一堆文件里按内容找
for i in $(seq 1 120); do printf 'noise line %s\n' "$i" > "$R/many/n$i.txt"; done
printf 'flag{grep_r_content_2b9d}\n' > "$R/many/n87.txt"

# T3 按大小找（正好 1337 字节）
{ printf 'flag{find_by_size_5c3e}\n'; head -c 1337 /dev/zero; } | head -c 1337 > "$R/perm/size1337.bin"

# T4 按权限找（SUID）
printf 'flag{find_suid_9f2a}\n' > "$R/perm/suid_note.txt"
chmod 4755 "$R/perm/suid_note.txt"

# T5 按修改时间找
printf 'flag{find_mmin_4d8b}\n' > "$R/perm/recent.txt"

# T6 隐藏文件
printf 'flag{hidden_dotfile_6e1f}\n' > "$R/.flag6_hidden"

# T7 日志统计（403 正好 17 条）
{
  for i in $(seq 1 60); do
    printf '10.0.0.%d - - [28/Oct/2026:10:00:%02d +0800] "GET /p%d HTTP/1.1" 200 512\n' "$((i % 9 + 1))" "$((i % 60))" "$i"
  done
  for i in $(seq 1 17); do
    printf '10.0.0.9 - - [28/Oct/2026:10:01:%02d +0800] "GET /admin%d HTTP/1.1" 403 233\n' "$((i % 60))" "$i"
  done
} > "$R/logs/access.log"

# T8 base64
printf 'flag{base64_then_cat_1a5c}\n' | base64 -w0 > "$R/enc/b64.txt"

# T9 tar.gz
mkdir -p "$R/arch/pkg"
printf 'flag{tar_tzf_xzf_3c7d}\n' > "$R/arch/pkg/readme.txt"
tar czf "$R/arch/archive.tar.gz" -C "$R/arch" pkg
rm -rf "$R/arch/pkg"

# T10 没有扩展名的文件（其实是 zip）
printf 'flag{file_says_zip_8b2e}\n' > /tmp/_mk10_flag.txt
python3 - "$R/bin/mystery" /tmp/_mk10_flag.txt <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as z:
    z.write(sys.argv[2], "flag.txt")
PY
rm -f /tmp/_mk10_flag.txt

# 把所有文件的修改时间拨回 7 天前，只留 T5 那个是「刚刚」
# （这样你练 40 分钟甚至一小时后，-mtime -1 仍然只命中它）
find "$R" -type f -exec touch -d '7 days ago' {} +
touch "$R/perm/recent.txt"

echo "环境已布置：$R"
echo "10 道题看 questions.md；做完跑：python3 check.py"
ls -la "$R"
