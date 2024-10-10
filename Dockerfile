FROM golang:1.22-alpine AS builder

RUN apk add --no-cache musl-dev git gcc

ADD . /src

WORKDIR /src

ENV CGO_ENABLED=0

RUN cd cmd/gost && go env && go build

FROM alpine:3.20

# add iptables for tun/tap
RUN apk add --no-cache iptables

WORKDIR /bin/

COPY --from=builder /src/cmd/gost/gost .

ENTRYPOINT ["/bin/gost"]
