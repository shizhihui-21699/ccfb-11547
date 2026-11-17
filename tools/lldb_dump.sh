#!/usr/bin/env bash
# lldb_dump.sh —— 用平台调试器从进程外部抓取目标进程的全部可读内存,
# 然后离线搜索哨兵残留。
#
# 与进程内 memscan 的区别: 这是 "攻击者/取证人员视角", 不依赖目标进程配合,
# 能抓到进程自己 (因 bug 或被篡改) 不愿报告的内容。
#
# 用法:
#   ./lldb_dump.sh <pid> <needle_hex> [needle_hex ...]
#
# 输出:
#   - 内存镜像写入 /tmp/memdump-<pid>.bin (区域清单 .map)
#   - 每个 needle 的命中次数和还原后的虚拟地址
#
# 注意: macOS 上 lldb 附加同用户进程默认允许; 对 hardened/受保护进程,
# 附加本身会被系统审计 —— 这也是 mlock/禁 core 之外的一层保护。

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "用法: $0 <pid> <needle_hex> [needle_hex ...]" >&2
    exit 2
fi

PID="$1"
shift
OUT="/tmp/memdump-${PID}.bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

rm -f "$OUT" "${OUT}.map"

echo "[*] 附加进程 ${PID} 并抓取内存..."
DUMP_PID="$PID" DUMP_OUT="$OUT" lldb --batch \
    -o "command script import ${SCRIPT_DIR}/lldb_dump.py" \
    >/dev/null

if [[ ! -s "$OUT" ]]; then
    echo "[!] 镜像为空或抓取失败" >&2
    exit 1
fi

echo "[*] 镜像: $OUT ($(stat -f%z "$OUT" 2>/dev/null || stat -c%s "$OUT") 字节)"
echo "[*] 区域清单: ${OUT}.map"
echo

# 离线搜索: python -I 隔离模式, 不加载工作目录模块
python3 -I - "$OUT" "$@" <<'PYEOF'
import sys, binascii

dump_path = sys.argv[1]
needles_hex = sys.argv[2:]
with open(dump_path, "rb") as f:
    data = f.read()

ranges = []
with open(dump_path + ".map") as f:
    for line in f:
        s, e, size = line.split()
        ranges.append((int(s, 16), int(e, 16), int(size)))

def vaddr_for(offset):
    cursor = 0
    for idx, (start, end, size) in enumerate(ranges):
        if cursor <= offset < cursor + size:
            return start + (offset - cursor), idx
        cursor += size
    return None, -1

total_residual = 0
for i, hx in enumerate(needles_hex):
    needle = binascii.unhexlify(hx)
    hits = []
    start = 0
    while True:
        j = data.find(needle, start)
        if j < 0:
            break
        hits.append(j)
        start = j + 1
    print("needle#%d (%d 字节): %d 处命中" % (i, len(needle), len(hits)))
    for off in hits[:10]:
        va, ridx = vaddr_for(off)
        if va is not None:
            rstart, rend, rsize = ranges[ridx]
            # 受保护容器是独立页级映射 (典型 16KB); malloc 堆是 MB 级巨型匿名区
            kind = "受保护小页(mlock)" if rsize <= 1 << 17 else "普通堆/大匿名区"
            print("    虚拟地址 %#x  所在区域 %#x+%#x (%s)" % (va, rstart, rsize, kind))
        else:
            print("    偏移 %#x" % off)
    if len(hits) > 10:
        print("    ... 另有 %d 处" % (len(hits) - 10))
    total_residual += len(hits)

print()
print("== 总残留命中: %d ==" % total_residual)
sys.exit(0 if total_residual == 0 else 3)
PYEOF
