FROM rust:1.75-alpine AS rust-builder

WORKDIR /app
RUN apk add --no-cache musl-dev

# 构建 Rust 转换库
COPY transform ./transform
COPY crates ./crates
RUN cd transform && cargo build --release

FROM golang:1.21-alpine AS go-builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

# 复制 Rust 库
COPY --from=rust-builder /app/transform/target/release/librekrypt_transform.a ./lib/
COPY main.go ./
RUN CGO_ENABLED=1 go build -o proxy main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=go-builder /app/proxy .
EXPOSE 8080
CMD ["./proxy"]
