FROM golang:1.24 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /ai-relay-gateway ./cmd/ai-relay-gateway
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /ai-relay-gateway /usr/local/bin/ai-relay-gateway
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/ai-relay-gateway"]
