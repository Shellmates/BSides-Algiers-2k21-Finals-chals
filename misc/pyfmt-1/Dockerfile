FROM python:3-alpine

RUN apk update && \
    apk add socat

RUN adduser --disabled-password --no-create-home ctf

COPY challenge /challenge/

WORKDIR /challenge

RUN chmod +x challenge.py entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
