FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y  python3 socat

RUN useradd -m -d /home/zerocool -s /bin/bash zerocool

COPY challenge/flag /Flag
RUN chmod 444 /Flag 

WORKDIR /home/zerocool
COPY challenge/entry.sh entry.sh
COPY challenge/chall.sh chall.sh
RUN chmod 555 entry.sh
RUN chmod 555 chall.sh

EXPOSE 7001

USER zerocool

ENTRYPOINT /home/zerocool/entry.sh