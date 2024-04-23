#! /bin/sh

pod=$(kubectl get pod -n kmesh-system | grep kmesh |
# 使用 awk 提取第一列
awk '{print $1}')


kubectl port-forward $pod -n kmesh-system  --address 0.0.0.0  15200:15200