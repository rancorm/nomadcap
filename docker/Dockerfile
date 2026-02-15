FROM alpine:3.21

RUN apk add --no-cache \
    libpcap \
    libcsv \
    jansson \
    ieee-data

COPY build/nomadcap /usr/local/bin/nomadcap
COPY build/nomadcap6 /usr/local/bin/nomadcap6

ENTRYPOINT ["/usr/local/bin/nomadcap"]
