FROM golang:1 as builder

ADD . /data

WORKDIR /data

RUN cd cmd/gost && go install

FROM alpine:latest

WORKDIR /bin/

COPY --from=builder /go/bin/gost .

ENTRYPOINT ["/bin/gost"]