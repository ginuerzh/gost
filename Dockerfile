FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.5.0 AS xx

FROM --platform=$BUILDPLATFORM golang:1.23-alpine3.20 AS builder

COPY --from=xx / /

ARG TARGETPLATFORM

RUN xx-info env

ENV CGO_ENABLED=0

ENV XX_VERIFY_STATIC=1

WORKDIR /app

COPY . .

RUN cd cmd/gost && \
    xx-go build && \
    xx-verify gost

FROM alpine:3.20

# add iptables for tun/tap
RUN apk add --no-cache iptables

WORKDIR /bin/

COPY --from=builder /app/cmd/gost/gost .

ENTRYPOINT ["/bin/gost"]