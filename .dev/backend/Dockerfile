FROM harbor.peinser.com/dockerhub/alpine:3.20

RUN apk add --no-cache socat

COPY udp-echo.sh /usr/local/bin/udp-echo
RUN chmod +x /usr/local/bin/udp-echo
ENTRYPOINT ["/usr/local/bin/udp-echo"]
