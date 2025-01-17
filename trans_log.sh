#!/bin/bash

# 定义文件名前缀
PREFIX="/home/weixiangjiang/CSAL_Artifact_Evaluation/raw/wzc_test/run_log/zipf081"

# 使用变量构建文件路径并执行 grep 命令
grep '\[WZC_thr\]' trace_vhost.log > "${PREFIX}_throttle.log"
grep '\[WZC_CMP_ED\]' trace_vhost.log > "${PREFIX}_cmp_ed.log"
grep '\[WZC_CMP\]' trace_vhost.log | grep -v '\[WZC_CMP_ED\]' > "${PREFIX}_tmp_read.log"

echo "trans_log success!"
