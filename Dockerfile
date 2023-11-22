FROM golang:alpine3.18 as go-builder
WORKDIR /usr/src/prom-http-sd
ADD . .
RUN go build -v

FROM alpine:3.18
LABEL org.opencontainers.image.source="github.com/mitch000001/prometheus-nmap-discovery"
RUN apk update && apk add nmap
COPY --from=go-builder /usr/src/prom-http-sd/prom-http-sd /usr/bin/prom-http-sd
ENTRYPOINT [ "/usr/bin/prom-http-sd" ]