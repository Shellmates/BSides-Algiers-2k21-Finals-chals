FROM ubuntu:18.04

RUN apt-get update && \
    apt-get install -y socat python3 gcc cron && \
    rm -rf /var/lib/apt/lists/* 

RUN useradd -m -d /home/ctf -s /bin/bash ctf
RUN useradd -s /bin/bash linus

COPY entrypoint.sh .

# CRON 
COPY clean /usr/bin
RUN chmod 700 /usr/bin/clean

RUN crontab -l | { cat; echo "*/5 * * * * /bin/bash /usr/bin/clean"; } | crontab -
RUN cron
# CRON END


WORKDIR /home/ctf

COPY flag.txt . 
COPY challenge/guess .
COPY challenge/secret .
COPY challenge/run .

RUN chown root:root /home/ctf
RUN chmod 555 /home/ctf

RUN chown root:linus flag.txt
RUN chmod 440 flag.txt

RUN chown root:linus secret
RUN chmod 440 secret

RUN chown root:root guess
RUN chmod 775 guess

RUN chown root:linus run
RUN chmod 750 secret

RUN chmod g+s run

USER ctf 


ENTRYPOINT ["/entrypoint.sh"]
