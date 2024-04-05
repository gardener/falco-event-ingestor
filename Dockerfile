#############      builder                                  #############
FROM golang:1.22.1 AS builder

WORKDIR /go/src/github.com/gardener/falco-event-ingestor
COPY . .

RUN mkdir -p bin && \
    go build -o bin ./...
#RUN make install && \
#    find /go

#############      base                                     #############
FROM gcr.io/distroless/static-debian11:nonroot as base
WORKDIR /

#############     falco-event-ingestor              #############
FROM base AS falco-event-ingestor

COPY --from=builder /go/src/github.com/gardener/falco-event-ingestor/bin/ingestor /falco-event-ingestor
ENTRYPOINT ["/falco-event-ingestor"]
