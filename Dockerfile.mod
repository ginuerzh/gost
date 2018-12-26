FROM golang:1-alpine as builder

RUN apk add --no-cache musl-dev git gcc

ADD . /data

WORKDIR /data

ENV GO111MODULE=on

RUN cd cmd/gost && go build

FROM alpine:latest

WORKDIR /bin/

COPY --from=builder /data/cmd/gost/gost .

RUN /bin/gost -V

ENTRYPOINT ["/bin/gost"]