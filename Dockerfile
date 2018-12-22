FROM golang:1-alpine as builder

ADD . /data

WORKDIR /data

ENV GO111MODULE=on

RUN cd cmd/gost && go build

FROM alpine:latest

WORKDIR /bin/

COPY --from=builder /data/cmd/gost/gost .

RUN ls /bin/ && /bin/gost -h

ENTRYPOINT ["/bin/gost"]