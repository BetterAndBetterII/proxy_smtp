# ---- 构建阶段 ----
# 使用官方的 Go Alpine 镜像作为构建环境，以获得更小的基础镜像
FROM golang:1.24-alpine AS builder

# 设置必要的环境变量，用于交叉编译一个静态的Linux可执行文件
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

# 设置工作目录
WORKDIR /app

# 复制 go.mod 文件并下载依赖
# 这样可以利用Docker的层缓存，只有在 go.mod 改变时才会重新下载依赖
COPY go.mod ./
RUN go mod download

# 复制所有源代码到工作目录
COPY . .

# 编译 Go 应用
# -a 强制重新构建
# -installsuffix cgo 避免使用cgo
# -ldflags "-w -s" 去除调试信息，减小二进制文件大小
# -o 指定输出文件名
RUN go build -a -installsuffix cgo -ldflags="-w -s" -o /proxy-smtp main.go


# ---- 运行阶段 ----
# 使用一个非常小的基础镜像
FROM alpine:latest

# Alpine 镜像默认不包含根证书，添加它们以便我们的应用可以验证TLS证书
RUN apk --no-cache add ca-certificates

# 设置工作目录
WORKDIR /app

# 从构建阶段复制编译好的二进制文件
COPY --from=builder /proxy-smtp /proxy-smtp

# 暴露容器的端口。
# 这只是元数据，实际端口映射在 docker run 时指定。
# 这里的端口应与 PROXY_LISTEN_ADDR 中的端口一致。
EXPOSE 2525

# 定义容器启动时运行的命令
ENTRYPOINT ["/proxy-smtp"] 