#############      builder                                  #############
FROM golang:1.21.4 AS builder

WORKDIR /go/src/github.com/gardener/falco-event-ingestor
COPY . .

RUN .ci/build

#############      base                                     #############
FROM gcr.io/distroless/static-debian11:nonroot as base
WORKDIR /

#############      machine-controller-manager               #############
FROM base AS machine-controller-manager

COPY --from=builder /go/src/github.com/gardener/falco-event-ingestor/bin/falco-event-ingestor /falco-event-ingestor
ENTRYPOINT ["/falco-event-ingestor"]
