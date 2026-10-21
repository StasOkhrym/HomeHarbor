FROM golang:1.27.3-alpine AS build
ARG TARGETARCH
WORKDIR /src
# The Go base already includes CA roots; public modules use the HTTPS proxy.
# Git metadata is excluded from the build context, so no extra apk tools are needed.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/control ./cmd/control && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/healthcheck ./cmd/healthcheck

FROM gcr.io/distroless/static-debian12:nonroot AS control
COPY --from=build /out/control /control
COPY --from=build /out/healthcheck /healthcheck
ENTRYPOINT ["/control"]

FROM gcr.io/distroless/static-debian12:nonroot AS relay
COPY --from=build /out/relay /relay
COPY --from=build /out/healthcheck /healthcheck
ENTRYPOINT ["/relay"]

FROM gcr.io/distroless/static-debian12:nonroot AS migrate
COPY --from=build /out/migrate /migrate
ENTRYPOINT ["/migrate"]
