FROM golang:1.21-alpine AS builder
WORKDIR /build

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o rekrypt-transform

FROM alpine:latest
WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/rekrypt-transform .

EXPOSE 8080
CMD ["./rekrypt-transform"]
