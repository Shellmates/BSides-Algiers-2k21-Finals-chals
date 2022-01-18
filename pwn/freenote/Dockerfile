FROM frolvlad/alpine-glibc:glibc-2.32

RUN apk update && apk add socat

COPY challenge /challenge
WORKDIR /challenge
RUN chmod 644 flag.txt && \
    chmod 500 run.sh

EXPOSE 1337

ENTRYPOINT ["/challenge/run.sh"]
