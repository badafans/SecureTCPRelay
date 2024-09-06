# 构建阶段
FROM golang:1.20-alpine AS builder
WORKDIR /app
COPY SecureTCPRelay.go .
RUN go mod init SecureTCPRelay
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o SecureTCPRelay .
# 运行阶段
FROM scratch
COPY --from=builder /app/SecureTCPRelay /SecureTCPRelay
ENTRYPOINT ["/SecureTCPRelay"]
CMD ["-h"]