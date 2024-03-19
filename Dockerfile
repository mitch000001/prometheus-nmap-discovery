FROM golang:alpine3.18 as go-builder
WORKDIR /usr/src/prom-http-sd
ADD . .
RUN go build -v

FROM alpine:3.18
LABEL org.opencontainers.image.source=https://github.com/mitch000001/prometheus-nmap-discovery
LABEL org.opencontainers.image.description="prometheus http service discovery server"
LABEL org.opencontainers.image.licenses=MIT
RUN apk update && apk add nmap
COPY --from=go-builder /usr/src/prom-http-sd/prom-http-sd /usr/bin/prom-http-sd
ENTRYPOINT [ "/usr/bin/prom-http-sd" ]