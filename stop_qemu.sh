#!/bin/bash

# 查找与 vhost 相关的进程 ID
pids=$(pgrep -f "qemu")

# 检查是否找到进程
if [ -z "$pids" ]; then
    echo "没有找到 qemu 进程"
else
    echo "停止 qemu 进程: $pids"
    # 杀死所有找到的进程
    echo "$pids" | xargs sudo kill -9
fi
