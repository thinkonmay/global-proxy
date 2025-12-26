# Build Stage
FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o server main.go

# Run Stage
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 8080
CMD ["./server"]