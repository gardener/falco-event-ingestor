#############      builder                                  #############
FROM golang:1.23.3 AS builder

WORKDIR /go/src/github.com/gardener/falco-event-ingestor
COPY . .

RUN mkdir -p bin && \
    CGO_ENABLED=0 GO111MODULE=on go build -o "bin/falco-event-ingestor" cmd/ingestor/main.go

#############      base                                     #############
FROM gcr.io/distroless/static-debian11:nonroot as base
WORKDIR /

#############     falco-event-ingestor              #############
FROM base AS falco-event-ingestor

COPY --from=builder /go/src/github.com/gardener/falco-event-ingestor/bin/falco-event-ingestor /falco-event-ingestor
ENTRYPOINT ["/falco-event-ingestor"]
