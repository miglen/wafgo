# ---- build ----
FROM golang:1.27.2-alpine AS build
WORKDIR /src
# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=docker
# Static, stripped binary so it runs on scratch.
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/miglen/wafgo.Version=${VERSION}" \
      -o /out/wafgo ./cmd/wafgo

# ---- runtime ----
FROM scratch
# CA roots for HTTPS and crt.sh.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/wafgo /wafgo
# Run as a non-root UID.
USER 65534:65534
ENTRYPOINT ["/wafgo"]
