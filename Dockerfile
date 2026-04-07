FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o verifier .

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
RUN adduser -D -h /app appuser
WORKDIR /app
COPY --from=builder /app/verifier .
COPY static/ ./static/
USER appuser
EXPOSE 9090
CMD ["./verifier"]
