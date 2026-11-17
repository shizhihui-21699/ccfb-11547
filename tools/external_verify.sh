#!/usr/bin/env bash
# external_verify.sh —— 完整的外部取证验证流程。
#
# 对同一目标做两次 lldb 抓取:
#   1. 秘密持有期间: 期望 hardened 只在受保护小页命中, naive 在大堆块多处命中;
#   2. 服务关闭后 (SHUTDOWN_DONE): 期望 hardened 命中为 0。
#
# 用法: ./external_verify.sh <naive|hardened> [hold_seconds]

set -euo pipefail

MODE="${1:-hardened}"
SECONDS_HOLD="${2:-20}"
BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/debug/demo-service"
DUMP="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lldb_dump.sh"
LOG_TMP="$(mktemp -t hold)"
LOG="${LOG_TMP}.log"
mv "$LOG_TMP" "$LOG"

echo "############ 外部取证验证: $MODE 模式 ############"
nohup "$BIN" hold "$MODE" --seconds "$SECONDS_HOLD" > "$LOG" 2>&1 &
TARGET_PID=$!
# 等它打印 pid/needle
for _ in $(seq 1 20); do
    grep -q NEEDLE_TOK "$LOG" 2>/dev/null && break
    sleep 0.5
done

PID=$(grep -o 'PID=[0-9]*' "$LOG" | cut -d= -f2)
DB=$(grep NEEDLE_DB "$LOG" | cut -d= -f2)
KEY=$(grep NEEDLE_KEY "$LOG" | cut -d= -f2)
TOK=$(grep NEEDLE_TOK "$LOG" | cut -d= -f2)
echo "[阶段1] 秘密持有期间 (pid=$PID)"
# lldb_dump 在发现命中时返回 3, 这是预期结果而非脚本错误, 关闭 errexit
"$DUMP" "$PID" "$DB" "$KEY" "$TOK" 2>&1 | sed 's/^/  /' || true

if [[ "$MODE" == "hardened" ]]; then
    echo
    echo "[*] 等待服务关闭 (SHUTDOWN_DONE)..."
    for _ in $(seq 1 $((SECONDS_HOLD + 10))); do
        grep -q SHUTDOWN_DONE "$LOG" 2>/dev/null && break
        sleep 1
    done
    # 关闭后进程还会驻留最多 10 秒, 抓紧第二次抓取
    if ps -p "$PID" >/dev/null 2>&1; then
        echo "[阶段2] 服务关闭后, 进程仍驻留"
        "$DUMP" "$PID" "$DB" "$KEY" "$TOK" 2>&1 | sed 's/^/  /' || true
    else
        echo "[阶段2] 进程已退出; 检查无 core 文件:"
        ls -la /cores/core."$PID" 2>/dev/null || echo "  无 core 文件 (符合 RLIMIT_CORE=0 预期)"
    fi
fi

wait "$TARGET_PID" 2>/dev/null || true
rm -f "$LOG"
