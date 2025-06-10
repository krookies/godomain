#!/bin/bash

echo "正在构建子域名挖掘工具..."

# 清理旧的构建文件
rm -f godomain

# 下载依赖
echo "下载依赖..."
go mod tidy

# 构建应用
echo "编译应用..."
go build -o godomain .

if [ $? -eq 0 ]; then
    echo "构建成功！"
    echo "使用方法："
    echo "  图形界面模式: ./godomain -gui"
    echo "  命令行模式: ./godomain -host example.com"
else
    echo "构建失败！"
    exit 1
fi 