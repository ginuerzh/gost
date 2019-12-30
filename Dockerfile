FROM golang:1-alpine as builder

RUN apk add --no-cache musl-dev git gcc

ADD . /src

WORKDIR /src

ENV GO111MODULE=on

RUN cd cmd/gost && go build

FROM alpine:latest

WORKDIR /bin/

COPY --from=builder /src/cmd/gost/gost .

ENTRYPOINT ["/bin/gost"]
