# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder

WORKDIR /src

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILT_AT=unknown

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w \
      -X 'github.com/vtmattedi/mw-oauth-service/internal/buildinfo.Version=${VERSION}' \
      -X 'github.com/vtmattedi/mw-oauth-service/internal/buildinfo.Commit=${COMMIT}' \
      -X 'github.com/vtmattedi/mw-oauth-service/internal/buildinfo.BuiltAt=${BUILT_AT}'" \
    -o /out/mw-oauth-service \
    ./cmd/server

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -o /out/create-admin \
    ./cmd/create-admin

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S app \
    && adduser -S -G app app \
    && mkdir -p /app/data \
    && chown -R app:app /app

WORKDIR /app

COPY --from=builder /out/mw-oauth-service /app/mw-oauth-service
COPY --from=builder /out/create-admin /app/create-admin

USER app

EXPOSE 8282

ENTRYPOINT ["/app/mw-oauth-service"]
