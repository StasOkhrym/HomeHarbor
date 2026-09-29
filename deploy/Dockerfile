FROM golang:1.27.1-alpine AS build
ARG TARGETARCH
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/control ./cmd/control && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay

FROM gcr.io/distroless/static-debian12:nonroot AS control
COPY --from=build /out/control /control
ENTRYPOINT ["/control"]

FROM gcr.io/distroless/static-debian12:nonroot AS relay
COPY --from=build /out/relay /relay
ENTRYPOINT ["/relay"]
